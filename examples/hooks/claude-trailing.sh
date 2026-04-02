#!/usr/bin/env bash
set -euo pipefail

TRAILING_URL="${TRAILING_URL:-http://localhost:3001}"
TRAILING_API_KEY="${TRAILING_API_KEY:-}"
TRAILING_AGENT_ID="${TRAILING_AGENT_ID:-claude-code}"
TRAILING_AGENT_TYPE="${TRAILING_AGENT_TYPE:-claude}"
TRAILING_TIMEOUT="${TRAILING_TIMEOUT:-10}"
TRAILING_MAX_RETRIES="${TRAILING_MAX_RETRIES:-4}"
TRAILING_LOG_FILE="${TRAILING_LOG_FILE:-}"
CLAUDE_SESSION_ID="${CLAUDE_SESSION_ID:-}"
CLAUDE_CONVERSATION_DIR="${CLAUDE_CONVERSATION_DIR:-}"

stdin_file="$(mktemp)"
trap 'rm -f "${stdin_file}"' EXIT
cat >"${stdin_file}"

python3 - "${stdin_file}" <<'PY'
from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


def log(message: str) -> None:
    line = f"trailing hook: {message}"
    print(line, file=sys.stderr)
    log_file = os.getenv("TRAILING_LOG_FILE")
    if log_file:
        Path(log_file).expanduser().parent.mkdir(parents=True, exist_ok=True)
        with Path(log_file).expanduser().open("a", encoding="utf-8") as handle:
            handle.write(f"{line}\n")


def load_hook_payload(path: Path) -> Dict[str, Any]:
    raw = path.read_text(encoding="utf-8").strip()
    if not raw:
        return {}
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        log(f"failed to decode hook payload: {exc}")
        return {}
    return payload if isinstance(payload, dict) else {}


def locate_transcript(hook_payload: Dict[str, Any]) -> Optional[Path]:
    conversation_dir = os.getenv("CLAUDE_CONVERSATION_DIR", "").strip()
    session_id = os.getenv("CLAUDE_SESSION_ID", "").strip() or str(hook_payload.get("session_id") or "")

    candidates: List[Path] = []
    if conversation_dir:
        base = Path(conversation_dir).expanduser()
        for suffix in (".jsonl", ".json"):
            if session_id:
                candidates.extend(sorted(base.glob(f"**/*{session_id}*{suffix}")))
            candidates.extend(sorted(base.glob(f"**/*{suffix}")))

    transcript_path = hook_payload.get("transcript_path")
    if transcript_path:
        candidates.insert(0, Path(str(transcript_path)).expanduser())

    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


def parse_transcript(path: Path) -> List[Dict[str, Any]]:
    text = path.read_text(encoding="utf-8")
    stripped = text.strip()
    if not stripped:
        return []

    if stripped.startswith("{") or stripped.startswith("["):
        try:
            payload = json.loads(stripped)
        except json.JSONDecodeError:
            payload = None
        if isinstance(payload, list):
            items = [item for item in payload if isinstance(item, dict)]
            return items
        if isinstance(payload, dict):
            items = []
            for key in ("messages", "events", "conversation"):
                value = payload.get(key)
                if isinstance(value, list):
                    items.extend(item for item in value if isinstance(item, dict))
            return items

    items = []
    for line in stripped.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            items.append(item)
    return items


def extract_content_blocks(item: Dict[str, Any]) -> Iterable[Dict[str, Any]]:
    for candidate in (item.get("message"), item):
        if not isinstance(candidate, dict):
            continue
        content = candidate.get("content")
        if isinstance(content, list):
            for block in content:
                if isinstance(block, dict):
                    yield block


def extract_timestamp(item: Dict[str, Any], fallback: str) -> str:
    for candidate in (item.get("timestamp"), item.get("created_at"), item.get("createdAt")):
        if isinstance(candidate, str) and candidate:
            return candidate
    message = item.get("message")
    if isinstance(message, dict):
        for candidate in (message.get("timestamp"), message.get("created_at"), message.get("createdAt")):
            if isinstance(candidate, str) and candidate:
                return candidate
    return fallback


def normalize_tool_result_content(value: Any) -> Any:
    if isinstance(value, list):
        normalized = []
        for item in value:
            if isinstance(item, dict) and item.get("type") == "text":
                normalized.append(item.get("text"))
            else:
                normalized.append(item)
        return normalized
    return value


def extract_tool_uses(items: List[Dict[str, Any]], session_id: str) -> List[Dict[str, Any]]:
    tool_uses: Dict[str, Dict[str, Any]] = {}
    ordered_ids: List[str] = []

    for item in items:
        timestamp = extract_timestamp(item, time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
        message = item.get("message") if isinstance(item.get("message"), dict) else item
        role = str(message.get("role") or item.get("role") or "")

        for block in extract_content_blocks(item):
            block_type = block.get("type")
            if block_type == "tool_use":
                tool_use_id = str(block.get("id") or block.get("tool_use_id") or f"tool-{len(ordered_ids)}")
                if tool_use_id not in tool_uses:
                    ordered_ids.append(tool_use_id)
                tool_uses[tool_use_id] = {
                    "session_id": session_id,
                    "tool_use_id": tool_use_id,
                    "tool_name": str(block.get("name") or "unknown-tool"),
                    "tool_input": block.get("input") if isinstance(block.get("input"), (dict, list, str, int, float, bool)) else {},
                    "tool_response": None,
                    "timestamp": timestamp,
                    "message_role": role,
                }
            elif block_type == "tool_result":
                tool_use_id = str(block.get("tool_use_id") or "")
                if not tool_use_id:
                    continue
                tool_uses.setdefault(
                    tool_use_id,
                    {
                        "session_id": session_id,
                        "tool_use_id": tool_use_id,
                        "tool_name": "unknown-tool",
                        "tool_input": {},
                        "tool_response": None,
                        "timestamp": timestamp,
                        "message_role": role,
                    },
                )
                tool_uses[tool_use_id]["tool_response"] = normalize_tool_result_content(block.get("content"))
                tool_uses[tool_use_id]["result_is_error"] = bool(block.get("is_error"))

        if "tool_name" in item:
            tool_use_id = str(item.get("tool_use_id") or item.get("id") or f"tool-{len(ordered_ids)}")
            if tool_use_id not in tool_uses:
                ordered_ids.append(tool_use_id)
            tool_uses[tool_use_id] = {
                "session_id": session_id,
                "tool_use_id": tool_use_id,
                "tool_name": str(item.get("tool_name") or "unknown-tool"),
                "tool_input": item.get("tool_input", {}),
                "tool_response": item.get("tool_response"),
                "timestamp": timestamp,
                "message_role": role,
            }

    return [tool_uses[tool_use_id] for tool_use_id in ordered_ids]


def build_action(tool_use: Dict[str, Any], transcript_path: Path, hook_payload: Dict[str, Any]) -> Dict[str, Any]:
    tool_name = str(tool_use.get("tool_name") or "unknown-tool")
    tool_input = tool_use.get("tool_input")
    target = None
    if isinstance(tool_input, dict):
        for key in ("file_path", "path", "target", "resource", "url", "command"):
            if tool_input.get(key):
                target = str(tool_input[key])
                break

    return {
        "session_id": tool_use["session_id"],
        "agent": os.getenv("TRAILING_AGENT_ID", "claude-code"),
        "agent_id": os.getenv("TRAILING_AGENT_ID", "claude-code"),
        "agent_type": os.getenv("TRAILING_AGENT_TYPE", "claude"),
        "type": "tool_call",
        "tool_name": tool_name,
        "tool": tool_name,
        "name": tool_name,
        "target": target,
        "timestamp": tool_use.get("timestamp"),
        "parameters": tool_input if isinstance(tool_input, dict) else {"input": tool_input},
        "result": tool_use.get("tool_response"),
        "status": "error" if tool_use.get("result_is_error") else "ok",
        "context": {
            "hook_event_name": hook_payload.get("hook_event_name", "SessionEnd"),
            "hook_reason": hook_payload.get("reason"),
            "tool_use_id": tool_use.get("tool_use_id"),
            "message_role": tool_use.get("message_role"),
            "transcript_path": str(transcript_path),
            "cwd": hook_payload.get("cwd"),
        },
    }


def post_action(action: Dict[str, Any]) -> None:
    base_url = os.getenv("TRAILING_URL", "http://localhost:3001").rstrip("/")
    api_key = os.getenv("TRAILING_API_KEY", "")
    timeout = float(os.getenv("TRAILING_TIMEOUT", "10"))
    max_retries = max(1, int(os.getenv("TRAILING_MAX_RETRIES", "4")))
    body = json.dumps({"actions": [action]}).encode("utf-8")

    headers = {"content-type": "application/json", "accept": "application/json"}
    if api_key:
        headers["x-api-key"] = api_key

    request = urllib.request.Request(
        f"{base_url}/v1/traces",
        data=body,
        headers=headers,
        method="POST",
    )

    for attempt in range(1, max_retries + 1):
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                if 200 <= response.status < 300:
                    return
                raise urllib.error.HTTPError(
                    request.full_url,
                    response.status,
                    response.reason,
                    response.headers,
                    None,
                )
        except urllib.error.HTTPError as exc:
            retryable = exc.code >= 500 or exc.code == 429
            if attempt >= max_retries or not retryable:
                raise
            sleep_for = min(2 ** (attempt - 1), 8)
            log(f"retrying tool {action.get('tool_name')} after HTTP {exc.code} in {sleep_for}s")
            time.sleep(sleep_for)
        except urllib.error.URLError:
            if attempt >= max_retries:
                raise
            sleep_for = min(2 ** (attempt - 1), 8)
            log(f"retrying tool {action.get('tool_name')} after network failure in {sleep_for}s")
            time.sleep(sleep_for)


def main() -> int:
    hook_payload = load_hook_payload(Path(sys.argv[1]))
    session_id = os.getenv("CLAUDE_SESSION_ID", "").strip() or str(hook_payload.get("session_id") or "")
    if not session_id:
        log("missing CLAUDE_SESSION_ID and hook payload session_id")
        return 0

    transcript_path = locate_transcript(hook_payload)
    if transcript_path is None:
        log("could not locate transcript from CLAUDE_CONVERSATION_DIR or transcript_path")
        return 0

    try:
        items = parse_transcript(transcript_path)
    except Exception as exc:
        log(f"failed to parse transcript {transcript_path}: {exc}")
        return 0

    tool_uses = extract_tool_uses(items, session_id)
    if not tool_uses:
        log(f"no tool uses found in {transcript_path}")
        return 0

    posted = 0
    failed = 0
    for tool_use in tool_uses:
        action = build_action(tool_use, transcript_path, hook_payload)
        try:
            post_action(action)
            posted += 1
        except Exception as exc:
            failed += 1
            log(f"failed to post tool {action.get('tool_name')} ({tool_use.get('tool_use_id')}): {exc}")

    log(f"processed {len(tool_uses)} tool uses, posted={posted}, failed={failed}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
PY
