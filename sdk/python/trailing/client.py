from __future__ import annotations

import asyncio
import datetime as dt
import functools
import http.client
import json
import os
import queue
import threading
import time
import urllib.parse
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Mapping

from .models import SdkEvent
from .redaction import RedactionConfig
from .retry import RetryConfig


JsonDict = dict[str, Any]


class TrailingError(Exception):
    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        response_text: str | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.response_text = response_text


@dataclass(slots=True)
class _FlushRequest:
    done: threading.Event
    error: BaseException | None = None


@dataclass(slots=True)
class _CloseRequest:
    done: threading.Event
    error: BaseException | None = None


class _BackgroundBatcher:
    def __init__(
        self,
        *,
        send_batch: Callable[[list[SdkEvent]], JsonDict],
        batch_size: int,
        flush_interval: float,
        max_queue_size: int,
    ) -> None:
        self._send_batch = send_batch
        self._batch_size = max(1, batch_size)
        self._flush_interval = max(0.01, flush_interval)
        self._queue: queue.Queue[SdkEvent | _FlushRequest | _CloseRequest] = queue.Queue(
            maxsize=max_queue_size
        )
        self._closed = False
        self._last_error: BaseException | None = None
        self._worker = threading.Thread(target=self._run, name="trailing-batcher", daemon=True)
        self._worker.start()

    def enqueue(self, event: SdkEvent) -> None:
        if self._closed:
            raise TrailingError("background sender is closed")
        if self._last_error is not None:
            raise TrailingError(f"background sender failed: {self._last_error}") from self._last_error
        self._queue.put(event)

    def flush(self) -> None:
        request = _FlushRequest(done=threading.Event())
        self._queue.put(request)
        request.done.wait()
        if request.error is not None:
            raise TrailingError(f"background flush failed: {request.error}") from request.error
        if self._last_error is not None:
            raise TrailingError(f"background sender failed: {self._last_error}") from self._last_error

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        request = _CloseRequest(done=threading.Event())
        self._queue.put(request)
        request.done.wait()
        self._worker.join(timeout=1.0)
        if request.error is not None:
            raise TrailingError(f"background sender failed while closing: {request.error}") from request.error
        if self._last_error is not None:
            raise TrailingError(f"background sender failed: {self._last_error}") from self._last_error

    def _run(self) -> None:
        batch: list[SdkEvent] = []
        last_activity = time.monotonic()

        while True:
            timeout = self._flush_interval if batch else None
            try:
                item = self._queue.get(timeout=timeout)
            except queue.Empty:
                self._flush_batch(batch)
                batch = []
                last_activity = time.monotonic()
                continue

            if isinstance(item, SdkEvent):
                batch.append(item)
                if len(batch) >= self._batch_size:
                    self._flush_batch(batch)
                    batch = []
                last_activity = time.monotonic()
                continue

            if isinstance(item, _FlushRequest):
                if batch and time.monotonic() >= last_activity:
                    self._flush_batch(batch)
                    batch = []
                item.error = self._last_error
                item.done.set()
                continue

            if isinstance(item, _CloseRequest):
                if batch:
                    self._flush_batch(batch)
                item.error = self._last_error
                item.done.set()
                return

    def _flush_batch(self, batch: list[SdkEvent]) -> None:
        if not batch:
            return
        try:
            self._send_batch(list(batch))
            self._last_error = None
        except BaseException as exc:  # pragma: no cover
            self._last_error = exc


class TrailingClient:
    def __init__(
        self,
        base_url: str | None = None,
        api_key: str | None = None,
        timeout: float = 10.0,
        retry_config: RetryConfig | None = None,
        redaction_config: RedactionConfig | None = None,
        batch_size: int = 20,
        flush_interval: float = 1.0,
        max_queue_size: int = 1_000,
        enable_background_queue: bool = True,
    ) -> None:
        self.base_url = (base_url or os.getenv("TRAILING_URL") or "http://127.0.0.1:3001").rstrip(
            "/"
        )
        self._base_url_parts = urllib.parse.urlsplit(self.base_url)
        if self._base_url_parts.scheme not in {"http", "https"} or not self._base_url_parts.hostname:
            raise ValueError(f"unsupported TRAILING_URL: {self.base_url!r}")
        self.api_key = api_key if api_key is not None else os.getenv("TRAILING_API_KEY")
        self.timeout = timeout
        self.retry_config = retry_config or RetryConfig()
        self.redaction_config = redaction_config or RedactionConfig()
        self._connection_lock = threading.Lock()
        self._connection: http.client.HTTPConnection | http.client.HTTPSConnection | None = None
        self._batcher = (
            _BackgroundBatcher(
                send_batch=self.send_events,
                batch_size=batch_size,
                flush_interval=flush_interval,
                max_queue_size=max_queue_size,
            )
            if enable_background_queue
            else None
        )

    def __enter__(self) -> "TrailingClient":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def close(self) -> None:
        try:
            if self._batcher is not None:
                self._batcher.close()
        finally:
            self._close_connection()

    def flush(self) -> None:
        if self._batcher is not None:
            self._batcher.flush()

    def send_event(self, event: SdkEvent) -> JsonDict:
        return self._post_traces([event.to_dict()])

    def send_events(self, events: Iterable[SdkEvent]) -> JsonDict:
        payload = [event.to_dict() for event in events]
        return self._post_traces(payload)

    def enqueue(self, event: SdkEvent) -> None:
        if self._batcher is None:
            raise TrailingError("background queue is disabled")
        self._batcher.enqueue(event)

    def track(self, event: SdkEvent, *, background: bool = True) -> JsonDict | None:
        if background and self._batcher is not None:
            self.enqueue(event)
            return None
        return self.send_event(event)

    def ingest(
        self,
        agent_id: str,
        agent_type: str,
        session_id: str,
        action_type: str,
        tool_name: str | None,
        target: str | None,
        params: Mapping[str, Any] | None,
        result: Any,
        context: Mapping[str, Any] | None,
    ) -> JsonDict:
        action: JsonDict = {
            "agent": agent_id,
            "agent_id": agent_id,
            "agent_type": agent_type,
            "session_id": session_id,
            "timestamp": self._timestamp(),
            "action": {
                "action_type": action_type,
                "tool_name": tool_name,
                "target": target,
                "status": "ok",
                "parameters": dict(params or {}),
                "result": result,
            },
            "context": dict(context or {}),
        }
        return self._post_traces([action])

    def ingest_otel(self, otlp_payload: Mapping[str, Any]) -> JsonDict:
        return self._request("POST", "/v1/traces/otlp", json_body=dict(otlp_payload))

    def log_oversight(
        self,
        event_type: str,
        approver: str,
        scope: str,
        related_action_id: str | None = None,
        session_id: str | None = None,
        framework: str | None = None,
        note: str | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> JsonDict:
        payload: JsonDict = {
            "event_type": event_type,
            "approver": approver,
            "scope": scope,
            "severity": self._oversight_severity(event_type),
            "timestamp": self._timestamp(),
        }
        payload["note"] = (
            note if note is not None else f"{event_type} recorded by {approver} for {scope}"
        )
        if related_action_id is not None:
            payload["related_action_id"] = related_action_id
        if session_id is not None:
            payload["session_id"] = session_id
        if framework is not None:
            payload["framework"] = framework
        if metadata is not None:
            payload["metadata"] = dict(metadata)
        return self._request("POST", "/v1/oversight", json_body=payload)

    def get_actions(
        self,
        session_id: str | None = None,
        agent: str | None = None,
        from_time: str | None = None,
        to_time: str | None = None,
        action_type: str | None = None,
    ) -> list[JsonDict]:
        params = self._compact(
            {
                "session_id": session_id,
                "agent": agent,
                "from": from_time,
                "to": to_time,
                "type": action_type,
            }
        )
        response = self._request("GET", "/v1/actions", params=params)
        return list(response.get("actions", []))

    def get_compliance(self, framework: str = "eu-ai-act") -> JsonDict:
        return self._request("GET", f"/v1/compliance/{framework}")

    def verify_integrity(self) -> JsonDict:
        return self._request("GET", "/v1/integrity")

    def get_health(self) -> JsonDict:
        return self._request("GET", "/v1/health")

    def export_json(self, framework: str = "eu-ai-act") -> JsonDict:
        return self._request("POST", "/v1/export/json", json_body={"framework": framework})

    def export_pdf(self, framework: str = "eu-ai-act") -> bytes:
        return self._request(
            "POST",
            "/v1/export/pdf",
            json_body={"framework": framework},
            expect_json=False,
        )

    def _post_traces(self, actions: list[JsonDict]) -> JsonDict:
        return self._request("POST", "/v1/traces", json_body={"actions": actions})

    def _request(
        self,
        method: str,
        path: str,
        *,
        json_body: Mapping[str, Any] | None = None,
        params: Mapping[str, str] | None = None,
        expect_json: bool = True,
    ) -> Any:
        url = self._build_url(path, params)
        request_target = self._build_request_target(path, params)
        headers = {"accept": "application/json", "connection": "keep-alive"}
        body: bytes | None = None
        if json_body is not None:
            headers["content-type"] = "application/json"
            body = json.dumps(self.redaction_config.redact(dict(json_body))).encode("utf-8")
        if self.api_key:
            headers["x-api-key"] = self.api_key

        last_error: BaseException | None = None
        for attempt in range(1, self.retry_config.max_attempts + 1):
            try:
                status_code, response_bytes = self._perform_request(
                    method, request_target, headers, body
                )
            except (http.client.HTTPException, TimeoutError, OSError) as exc:
                last_error = exc
                self._close_connection()
                if attempt < self.retry_config.max_attempts:
                    time.sleep(self.retry_config.next_delay(attempt))
                    continue
                raise TrailingError(f"request failed for {method} {url}: {exc}") from exc

            if status_code >= 400:
                if (
                    self.retry_config.should_retry_status(status_code)
                    and attempt < self.retry_config.max_attempts
                ):
                    time.sleep(self.retry_config.next_delay(attempt))
                    continue
                raise self._build_http_error(method, path, status_code, response_bytes)

            if not expect_json:
                return response_bytes

            try:
                payload = json.loads(response_bytes.decode("utf-8"))
            except json.JSONDecodeError as exc:
                raise TrailingError(
                    f"{method} {path} returned invalid JSON",
                    status_code=status_code,
                    response_text=response_bytes.decode("utf-8", errors="replace"),
                ) from exc

            if not isinstance(payload, dict):
                raise TrailingError(
                    f"{method} {path} returned an unexpected payload type",
                    status_code=status_code,
                    response_text=response_bytes.decode("utf-8", errors="replace"),
                )
            return payload

        raise TrailingError(f"request failed for {method} {url}: {last_error}")

    def _build_http_error(
        self, method: str, path: str, status_code: int, response_bytes: bytes
    ) -> TrailingError:
        response_text = response_bytes.decode("utf-8", errors="replace")
        message = response_text
        try:
            payload = json.loads(response_text)
        except json.JSONDecodeError:
            payload = None
        if isinstance(payload, dict) and isinstance(payload.get("error"), str):
            message = payload["error"]
        return TrailingError(
            f"{method} {path} failed with status {status_code}: {message}",
            status_code=status_code,
            response_text=response_text,
        )

    def _build_url(self, path: str, params: Mapping[str, str] | None) -> str:
        url = f"{self.base_url}{path}"
        if not params:
            return url
        return f"{url}?{urllib.parse.urlencode(params)}"

    def _build_request_target(self, path: str, params: Mapping[str, str] | None) -> str:
        base_path = self._base_url_parts.path.rstrip("/")
        request_target = f"{base_path}{path}" if base_path else path
        if not request_target.startswith("/"):
            request_target = f"/{request_target}"
        if not params:
            return request_target
        return f"{request_target}?{urllib.parse.urlencode(params)}"

    def _perform_request(
        self,
        method: str,
        request_target: str,
        headers: Mapping[str, str],
        body: bytes | None,
    ) -> tuple[int, bytes]:
        with self._connection_lock:
            connection = self._get_connection()
            try:
                connection.request(method, request_target, body=body, headers=dict(headers))
                response = connection.getresponse()
            except BaseException:
                self._close_connection_locked()
                raise

            try:
                status_code = response.status
                response_bytes = response.read()
                should_close = response.will_close
            except BaseException:
                self._close_connection_locked()
                raise
            finally:
                response.close()

            if should_close:
                self._close_connection_locked()

            return status_code, response_bytes

    def _get_connection(self) -> http.client.HTTPConnection | http.client.HTTPSConnection:
        if self._connection is None:
            connection_cls = (
                http.client.HTTPSConnection
                if self._base_url_parts.scheme == "https"
                else http.client.HTTPConnection
            )
            self._connection = connection_cls(
                self._base_url_parts.hostname,
                port=self._base_url_parts.port,
                timeout=self.timeout,
            )
        return self._connection

    def _close_connection(self) -> None:
        with self._connection_lock:
            self._close_connection_locked()

    def _close_connection_locked(self) -> None:
        if self._connection is None:
            return
        self._connection.close()
        self._connection = None

    def _compact(self, values: Mapping[str, str | None]) -> dict[str, str]:
        return {key: value for key, value in values.items() if value is not None}

    def _oversight_severity(self, event_type: str) -> str:
        lowered = event_type.lower()
        if lowered in {"override", "kill_switch", "kill-switch"}:
            return "high"
        if lowered in {"approval", "escalation"}:
            return "medium"
        return "low"

    def _timestamp(self) -> str:
        return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


class AsyncTrailingClient:
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self._sync_client = TrailingClient(*args, **kwargs)
        self._closed = False

    async def _run_in_executor(self, func: Callable[..., Any], /, *args: Any, **kwargs: Any) -> Any:
        loop = asyncio.get_running_loop()
        call = functools.partial(func, *args, **kwargs)
        return await loop.run_in_executor(None, call)

    async def __aenter__(self) -> "AsyncTrailingClient":
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.close()

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        await self._run_in_executor(self._sync_client.close)

    async def flush(self) -> None:
        await self._run_in_executor(self._sync_client.flush)

    async def send_event(self, event: SdkEvent) -> JsonDict:
        return await self._run_in_executor(self._sync_client.send_event, event)

    async def send_events(self, events: Iterable[SdkEvent]) -> JsonDict:
        return await self._run_in_executor(lambda: self._sync_client.send_events(list(events)))

    async def enqueue(self, event: SdkEvent) -> None:
        await self._run_in_executor(self._sync_client.enqueue, event)

    async def track(self, event: SdkEvent, *, background: bool = True) -> JsonDict | None:
        return await self._run_in_executor(self._sync_client.track, event, background=background)

    async def ingest(
        self,
        agent_id: str,
        agent_type: str,
        session_id: str,
        action_type: str,
        tool_name: str | None,
        target: str | None,
        params: Mapping[str, Any] | None,
        result: Any,
        context: Mapping[str, Any] | None,
    ) -> JsonDict:
        return await self._run_in_executor(
            self._sync_client.ingest,
            agent_id,
            agent_type,
            session_id,
            action_type,
            tool_name,
            target,
            params,
            result,
            context,
        )

    async def ingest_otel(self, otlp_payload: Mapping[str, Any]) -> JsonDict:
        return await self._run_in_executor(lambda: self._sync_client.ingest_otel(dict(otlp_payload)))

    async def log_oversight(
        self,
        event_type: str,
        approver: str,
        scope: str,
        related_action_id: str | None = None,
        session_id: str | None = None,
        framework: str | None = None,
        note: str | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> JsonDict:
        return await self._run_in_executor(
            self._sync_client.log_oversight,
            event_type,
            approver,
            scope,
            related_action_id,
            session_id=session_id,
            framework=framework,
            note=note,
            metadata=metadata,
        )

    async def get_actions(
        self,
        session_id: str | None = None,
        agent: str | None = None,
        from_time: str | None = None,
        to_time: str | None = None,
        action_type: str | None = None,
    ) -> list[JsonDict]:
        return await self._run_in_executor(
            self._sync_client.get_actions, session_id, agent, from_time, to_time, action_type
        )

    async def get_compliance(self, framework: str = "eu-ai-act") -> JsonDict:
        return await self._run_in_executor(self._sync_client.get_compliance, framework)

    async def verify_integrity(self) -> JsonDict:
        return await self._run_in_executor(self._sync_client.verify_integrity)

    async def get_health(self) -> JsonDict:
        return await self._run_in_executor(self._sync_client.get_health)

    async def export_json(self, framework: str = "eu-ai-act") -> JsonDict:
        return await self._run_in_executor(self._sync_client.export_json, framework)

    async def export_pdf(self, framework: str = "eu-ai-act") -> bytes:
        return await self._run_in_executor(self._sync_client.export_pdf, framework)
