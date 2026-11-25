# AGENTS — arr/mylar

> Per-service notes. Read [../AGENTS.md](../AGENTS.md) first.

## Upstream API

- Canonical docs: <https://github.com/mylar3/mylar3/wiki/API-Documentation>
- Last verified: 2026-11-10
- Details: [docs/upstream/arr-mylar.md](../../docs/upstream/arr-mylar.md)

## Auth model

API key passed as `apikey` query parameter.
`New` key: empty or ASCII letters, digits, `-._~` only; other bytes -> fixed error, no input or parse cause in text.

- Request build, transport, response read: changed root `*url.Error` -> copy, `Op` + URL scrubbed, cause opaque (hideCause); classifier answers captured at copy time; nil and typed-nil causes preserved; untouched root keeps identity. URL: `apikey` values -> `REDACTED`; unparseable URL or query -> query dropped (redactURL).
- `APIError.Status` + `APIError.Body` on non-2xx. Literal key -> `REDACTED` inline (scrub). Decode percent-only, backslash-only, and mixed projections. Key match, >16 new texts per layer, or new text at layer 4 -> whole field `REDACTED`.
- Decode + request errors. Breadth-first walk, single + joined `Unwrap` links, 64 nodes. Key in `Error()` text, `%#v` output, or direct `*url.Error` fields `Op` + `URL`, decoded too, or custom `fmt.Formatter` / `fmt.GoStringer` -> opaque wrapper, scrubbed message (redactedError, carriesKey). Overflow or typed-nil node -> fixed message without formatting tree.
- Opaque wrapper. `errors.Is` (identity per node, nested wrappers included), `Timeout`, `Temporary` via depth-first walk, 64 joined errors + 4096 visited nodes. `errors.Is` budget shared with nested opaque wrappers. URL classification follows the immediate cause and captures both answers in one walk with the same bounds. `errors.As` copies first non-nil `*url.Error` within 64 breadth-first queued nodes, same cause handling as root copy.
