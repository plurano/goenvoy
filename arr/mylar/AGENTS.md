# AGENTS — arr/mylar

> Per-service notes. Read [../AGENTS.md](../AGENTS.md) first.

## Upstream API

- Canonical docs: <https://github.com/mylar3/mylar3/wiki/API-Documentation>
- Last verified: 2026-11-10
- Details: [docs/upstream/arr-mylar.md](../../docs/upstream/arr-mylar.md)

## Auth model

API key passed as `apikey` query parameter.
`New` key: empty or ASCII letters, digits, `-._~` only; other bytes -> fixed error, no input or parse cause in text.

- Request build, transport, response read: changed root `*url.Error` -> copy, `Op` + URL scrubbed, cause opaque (hideCause); classifier answers captured at copy time; nil and typed-nil causes preserved; untouched root keeps identity. Root + `errors.As` URL copies -> parse and redact `apikey` query values (redactURL), then literal key replacement + canonical check (scrubText). Unparseable URL or query -> query dropped.
- `APIError.Status` + `APIError.Body` on non-2xx. Literal key -> `REDACTED` inline (scrub). Decode percent-only, backslash-only, and mixed projections. Offset-anchored matcher -> literal, percent-encoded, or backslash-u spelling per key byte in input + each projection. Key match, >16 new texts per layer, or new text at layer 4 -> whole field `REDACTED`.
- Decode + request errors. Breadth-first walk, single + joined `Unwrap` links, 64 nodes. Key in `Error()` text, `%#v` output, or direct `*url.Error` fields `Op` + `URL`, decoded too, or custom `fmt.Formatter` / `fmt.GoStringer` / `As(any) bool` -> opaque wrapper, scrubbed message (redactedError, carriesKey). Overflow or typed-nil node -> fixed message without formatting tree.
- Opaque wrapper. `errors.Is` (identity per node, nested wrappers included), `Timeout`, `Temporary` via depth-first walk, 64 joined errors + 4096 visited nodes. `errors.Is` budget shared with nested opaque wrappers. Immediate URL cause implements `Timeout` or `Temporary` -> both classifications captured in one walk with same bounds. `errors.As` copies first non-nil `*url.Error` within 64 breadth-first queued nodes, same cause handling as root copy.
- Contract limits:
  - Raw percent sign or backslash directly before key spelled across two or more escape layers
  - Typed-nil causes below immediate cause classify false
  - `%#v` inherits fmt recursion on self-referential values
  - Formatting code emits key only on later call
  - Nested `*url.Error` with `apikey` value other than configured key
