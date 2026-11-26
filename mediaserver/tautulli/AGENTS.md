# AGENTS — mediaserver/tautulli

> Per-service notes. Read [../AGENTS.md](../AGENTS.md) first.

## Upstream API

- Canonical docs: <https://github.com/Tautulli/Tautulli/wiki/Tautulli-API-Reference>
- Last verified: 2026-11-10
- Details: [docs/upstream/mediaserver-tautulli.md](../../docs/upstream/mediaserver-tautulli.md)

## Auth model

API key passed as `apikey` query parameter against `/api/v2`.
`New` key: empty or ASCII letters, digits, `-._~` only; other bytes -> fixed error, no input or parse cause in text.

- URL parse, request build, transport, response read: changed root `*url.Error` -> sanitized copy; untouched root keeps identity.
- URL copies from root and `errors.As` -> redact `apikey` query, then replace literal keys and check escaped forms. Unparseable URL or query -> drop query.
- URL copy cause -> keep nil. Typed-nil or unsafe cause -> fixed opaque error with no classification. Safe cause -> scrubbed message.
- `APIError.RawBody` on HTTP status errors + envelope message errors (`APIError.StatusCode` numeric). Literal key -> inline `REDACTED`.
- Decode percent-only, backslash-only, and mixed projections. Match literal, percent, and backslash-u spellings per key byte at each offset.
- Key match, >16 new texts per layer, new text at layer 4, or retained projection bytes >8x input -> whole field `REDACTED`.
- Decode + request errors -> breadth-first walk, 64 nodes, single or joined `Unwrap`. Overflow or typed-nil node -> fixed message.
- Key in `Error` text, direct `*url.Error` fields, or reflected leaves -> opaque wrapper, scrubbed message.
- Reflection -> up to 1024 values per error node, start pointer only. Overflow or nested `fmt.Formatter` / `fmt.GoStringer` -> opaque wrapper.
- Custom `fmt.Formatter`, `fmt.GoStringer`, or `As` method on error node -> opaque wrapper.
- Opaque `errors.Is`, `Timeout`, and `Temporary` -> depth-first walk, 64 joined errors and 4096 nodes. Nested wrappers share `errors.Is` budget.
- Safe immediate URL cause implements `Timeout` or `Temporary` -> capture both answers in one walk.
- Opaque `errors.As` -> copy first non-nil `*url.Error` within 64 breadth-first nodes, same cause handling as root.
- Contract limits:
  - Raw percent sign or backslash directly before key spelled across two or more escape layers
  - `Error` method prints key only on later call
  - Nested `*url.Error` with `apikey` value other than configured key
