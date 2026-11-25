# AGENTS — arr/jackett

> Per-service notes. Read [../AGENTS.md](../AGENTS.md) first.

## Upstream API

- Canonical docs: <https://github.com/Jackett/Jackett/wiki/Jackett-API>
- Last verified: 2026-11-10
- Details: [docs/upstream/arr-jackett.md](../../docs/upstream/arr-jackett.md)

## Auth model

API key passed as `apikey` query parameter.
`New` key: empty or ASCII letters, digits, `-._~` only; other bytes -> fixed error, no input or parse cause in text. Base URL with `?` or `#` refused.

- Request build, transport, response read: changed root `*url.Error` -> copy, `Op` + URL scrubbed, cause opaque (hideCause); classifiers delegate to original immediate cause; nil or typed-nil cause -> nil; untouched root keeps identity. URL: `apikey` values -> `REDACTED`; unparseable URL or query -> query dropped (redactURL).
- `APIError.Status` + `APIError.Body` on non-2xx. Literal key -> `REDACTED` inline (scrub). Decode remaining percent escapes (either hex case) and backslash escapes up to four passes. Key found or fourth pass still changes text -> whole field `REDACTED`. Bodies also checked for fixed key forms after backslash-only decode.
- Decode + request errors. Breadth-first walk, single + joined `Unwrap` links, 64 nodes. Key in `Error()` text or direct `*url.Error` fields `Op` + `URL`, decoded too, or custom `fmt.Formatter` -> opaque wrapper, scrubbed message (redactedError, carriesKey). Overflow or typed-nil node -> fixed message without formatting tree.
- Opaque wrapper. `errors.Is` (identity per node, nested wrappers included), `Timeout`, `Temporary` via depth-first walk, 64 joined errors + 4096 visited nodes. `errors.Is` budget shared with nested opaque wrappers. URL classifiers inspect immediate cause only. `errors.As` copies first non-nil `*url.Error` within 64 breadth-first queued nodes, same cause handling as root copy.
