# AGENTS — mediaserver/tautulli

> Per-service notes. Read [../AGENTS.md](../AGENTS.md) first.

## Upstream API

- Canonical docs: <https://github.com/Tautulli/Tautulli/wiki/Tautulli-API-Reference>
- Last verified: 2026-11-10
- Details: [docs/upstream/mediaserver-tautulli.md](../../docs/upstream/mediaserver-tautulli.md)

## Auth model

API key passed as `apikey` query parameter against `/api/v2`.
`New` key: empty or ASCII letters, digits, `-._~` only; other bytes -> fixed error, no input or parse cause in text.

- URL parse, request build, transport, response read: changed root `*url.Error` -> copy, `Op` + URL scrubbed, cause opaque (hideCause); nil or typed-nil cause -> nil; untouched root keeps identity. URL: `apikey` values -> `REDACTED`; unparseable URL or query -> query dropped (redactURL).
- `APIError.RawBody` on HTTP status errors + envelope message errors (`APIError.StatusCode` numeric). Literal key -> `REDACTED` inline (scrub). Decode remaining percent escapes (either hex case) and backslash escapes up to four passes. Key found or fourth pass still changes text -> whole field `REDACTED`. Bodies also checked for fixed key forms after backslash-only decode.
- Decode + request errors. Breadth-first walk, single + joined `Unwrap` links, 64 nodes. Key in `Error()` text or direct `*url.Error` fields `Op` + `URL`, decoded too -> opaque wrapper, scrubbed message (redactedError, carriesKey). Overflow or typed-nil node -> fixed message without formatting tree.
- Opaque wrapper. `errors.Is` (identity per node, nested wrappers included), `Timeout`, `Temporary` via depth-first walk, 64 joined errors + 4096 visited nodes. Budget shared with nested wrappers. URL classifiers inspect immediate cause only. `errors.As` copies first non-nil `*url.Error` within 64 breadth-first queued nodes, cause opaque or nil.
