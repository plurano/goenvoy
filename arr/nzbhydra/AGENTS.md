# AGENTS — arr/nzbhydra

> Per-service notes. Read [../AGENTS.md](../AGENTS.md) first.

## Upstream API

- Canonical docs: <https://github.com/theotherp/nzbhydra2/wiki>
- Last verified: 2026-11-10
- Details: [docs/upstream/arr-nzbhydra.md](../../docs/upstream/arr-nzbhydra.md)

## Auth model

API key passed as `apikey` query parameter.
`New` key: empty or ASCII letters, digits, `-._~` only; other bytes -> fixed error, no input or parse cause in text.

- Request build, transport, response read: changed root `*url.Error` -> copy, `Op` + URL scrubbed, cause opaque (hideCause); nil or typed-nil cause -> nil; untouched root keeps identity. URL: `apikey` values -> `REDACTED`; unparseable URL or query -> query dropped (redactURL).
- `APIError.Status` + `APIError.Body` on non-2xx: literal key -> `REDACTED` inline (scrub); key left after one decode pass (percent escapes, either hex case; backslash escapes) -> whole field `REDACTED` (scrubBody); bodies also checked for fixed key forms after backslash-only decode.
- Decode + request errors: single + joined `Unwrap` links, breadth-first, 64 nodes; key in `Error()` text, decoded too -> opaque wrapper, scrubbed message (redactedError, carriesKey); overflow or typed-nil node -> fixed message, tree never formatted.
- Opaque wrapper: `errors.Is` (identity per node, nested wrappers included), `Timeout`, `Temporary` via depth-first walk, 64 joined errors + 4096 visited nodes, budget shared with nested wrappers; `errors.As` for `*url.Error` only: first non-nil URL error within 64 breadth-first queued nodes, copied, cause opaque or nil.
