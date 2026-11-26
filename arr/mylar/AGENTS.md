# AGENTS — arr/mylar

> Per-service notes. Read [../AGENTS.md](../AGENTS.md) first.

## Upstream API

- Canonical docs: <https://github.com/mylar3/mylar3/wiki/API-Documentation>
- Last verified: 2026-11-10
- Details: [docs/upstream/arr-mylar.md](../../docs/upstream/arr-mylar.md)

## Auth model

API key passed as `apikey` query parameter.
`New` key: empty or ASCII letters, digits, `-._~` only; other bytes -> fixed error, no input or parse cause in text.

- Request build, transport, response read: changed root `*url.Error` -> sanitized copy; untouched root keeps identity.
- URL copies from root and `errors.As` -> redact `apikey` query, then replace literal keys and check escaped forms. Unparseable URL or query -> drop query.
- URL copy cause -> keep nil. Typed-nil or unsafe cause -> fixed opaque error with no classification. Safe cause -> scrubbed message.
- `APIError.Status` + `APIError.Body` on non-2xx. Literal key -> inline `REDACTED`.
- Decode percent-only, backslash-only, and mixed projections.
- Match literal, percent, and backslash-u spellings per key byte. Hex digits -> ASCII only.
- Spelling comparison limit -> `maxSpellingStepsFactor` (8) × text bytes plus key bytes.
- Key match or spelling comparison limit -> whole field `REDACTED`.
- More than 16 new projections per layer, new projection at layer 4, or retained storage above 8× input -> whole field `REDACTED`.
- Retained projection storage -> charge parent length, matching builder growth.
- Decode + request errors -> breadth-first walk, 64 nodes, single or joined `Unwrap`. Overflow or typed-nil node -> fixed message.
- Key in `Error` text, direct `*url.Error` fields, or reflected leaves -> opaque wrapper, scrubbed message.
- Reflection -> up to 1024 values per error node, start pointer only. Overflow or nested `fmt.Formatter` / `fmt.GoStringer` -> opaque wrapper.
- Custom `fmt.Formatter`, `fmt.GoStringer`, or `As` method on error node -> opaque wrapper.
- Wrapper with another captured key -> opaque boundary for classification and URL recovery.
- Opaque identity and classification walks -> depth-first, 64 joined errors and 4096 nodes. Nested wrappers share `errors.Is` budget.
- Stdlib classifier delegation (`*net.OpError`, `*os.SyscallError`, `*fs.PathError`, `*url.Error`) -> followed inside that walk; As-supplied package or stdlib wrapper -> false.
- Unsafe tree -> `Timeout` and `Temporary` false on wrapper and URL copy.
- Package-owned URL causes end classification -> opaque cause false, classified cause captured values.
- Safe immediate URL cause implements `Timeout` or `Temporary` -> capture both answers in one walk.
- Opaque `errors.As` -> copy first non-nil `*url.Error` within 64 breadth-first nodes, same cause handling as root.
- Contract limits:
  - Raw percent sign or backslash directly before key spelled across two or more escape layers
  - `Error` method prints key only on later call
  - Nested `*url.Error` with `apikey` value other than configured key
  - XML or HTML character references and escape schemes other than percent and backslash-u.
  - Custom `Timeout`, `Temporary` or `As` methods that call back into a package wrapper.
