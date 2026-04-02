# Known Issues & Technical Debt

## Stubs / Fakes

### vendor/uuid
`vendor/uuid/src/lib.rs` is a stub — not the real `uuid` crate. Generates UUIDs using a custom implementation. Should be replaced with the real `uuid` crate from crates.io.

### PDF export
`src/export/pdf.rs` generates a basic PDF but may not produce a fully valid PDF binary in all cases. The original vendor/genpdf was a stub and was replaced but the replacement needs verification.

### Compliance evaluation
`src/policy/evaluate.rs` + framework-specific files check basic conditions (action count > 0, oversight count > 0) rather than deep evidence analysis. Controls are evaluated with simple boolean logic, not actual policy matching.

## Incomplete features

### Multi-tenant auth
The auth agent (`real-auth`) was building API key management and org isolation but the computer crashed mid-write. The code in `src/storage/mod.rs` has API key creation/validation but it may be partially implemented. Needs verification:
- Does `trailing keys create` work?
- Does org isolation actually filter actions?
- Is the admin endpoint functional?

### File watcher
`src/watcher/mod.rs` was built by the `real-connect` agent. The `trailing watch` command may exist but needs testing:
- Does it actually parse Claude Code session JSON?
- Does it deduplicate on restart?

### HTTP proxy
`src/proxy/mod.rs` exists but was built by an agent and had a compilation error (fixed: `From<IngestError>` impl added). The proxy test had a flaky assertion. Needs end-to-end testing.

### SSE streaming
`src/api/mod.rs` may have SSE endpoint code from the `realtime-sse` agent, but it's not wired into the dashboard. Dashboard still polls every 5 seconds.

## UI issues

### Dashboard
- Oversight Events card shows correct count but "View all" link doesn't navigate (just text)
- Today/7D/30D buttons in topbar are decorative — don't filter data
- Mobile responsiveness is minimal
- No loading skeleton states
- Expanded table rows don't collapse when switching views

### Landing page
- Hamburger menu button exists but has no JS behavior (mobile nav doesn't open)
- "Book a Demo" links to /dashboard (no actual booking flow)
- Grid background only shows on body, not through section backgrounds

## Testing gaps
- No tests for file watcher, HTTP proxy end-to-end, or SSE streaming
- No tests for multi-tenant isolation
- Edge case tests exist (29) but some may reference old API shapes
- No browser/E2E tests for dashboard

## Infrastructure
- No GitHub repo created yet
- trailing.ai domain not purchased yet
- Docker image not tested beyond build
- CI/CD pipelines exist but haven't been run (no remote repo)
