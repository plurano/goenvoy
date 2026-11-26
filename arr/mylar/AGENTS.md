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
- Opaque identity walk -> depth-first, 4096 nodes and 64 joined errors. Nested wrappers share `errors.Is` budget.
- Stdlib classifier delegation (`*net.OpError`, `*os.SyscallError`, `*fs.PathError`, `*url.Error`) -> followed during classification.
- Classification skips custom `As` methods and continues into their `Unwrap` tree.
- External `Timeout` or `Temporary` method -> false when its `Unwrap` tree (64 nodes)
  holds a package wrapper or is unsafe.
- Classification reads each wrapper tree once within 64 nodes and classifies from that read.
- A same-key wrapper entered during classification is read once the same way.
- All reads of one classification share a budget of 4096 visited nodes.
- Unsafe tree -> `Timeout` and `Temporary` false.
- Package-owned URL causes end classification -> opaque cause false, classified cause captured values.
- Safe immediate URL cause implements `Timeout` or `Temporary` -> read its tree once and use it for both classifications.
- Opaque `errors.As` -> copy first non-nil `*url.Error` within 64 breadth-first nodes, same cause handling as root.
- Contract limits:
  - Raw percent sign or backslash directly before key spelled across two or more escape layers
  - `Error` method prints key only on later call
  - Nested `*url.Error` with `apikey` value other than configured key
  - XML or HTML character references and escape schemes other than percent and backslash-u.
  - Custom `Timeout` or `Temporary` methods that reach a package wrapper outside their `Unwrap` tree.
  - Key that also occurs in key-independent text (`REDACTED` placeholder, fixed messages, Go-syntax
    type names, field names or pointer addresses) -> that text stays because it carries no key-derived bytes.
