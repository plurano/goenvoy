// Package mylar provides a client for the Mylar3 API.
//
// Mylar3 is an automated comic book downloader and manager.
// Authentication uses an API key passed as a query parameter.
//
// Key matching → literal, percent, and backslash-u spellings per byte.
// Hex digits → ASCII only.
// Escape decoding → percent-only, backslash-only, and mixed projections.
// Spelling comparison limit → maxSpellingStepsFactor (8) × text bytes plus key bytes.
// Literal key → inline REDACTED.
// Escaped key spelling left after literal replacement or spelling comparison limit → whole field REDACTED.
// More than 16 new projections per layer, new projection at layer four,
// or retained storage above 8× input → whole-field redaction.
// Retained projection storage → charge parent length, matching builder growth.
// Error redaction scans up to 64 nodes for structural inspection and URL recovery.
// Key in Error text, direct URL error fields, or reflected leaves → opaque wrapper.
// After the check, one method-free re-read of recorded node fields (URL error Op and URL,
// reflected visible values) → key found → opaque wrapper.
// Reflection checks up to 1024 values per node and follows only the start pointer.
// Overflow or a nested fmt.Formatter or fmt.GoStringer → opaque wrapper.
// Custom formatting or As on an error node → opaque wrapper.
// Wrapper with this client's key → retain the inner wrapper.
// Key in outer error text, URL error fields or reflected values → opaque wrapper for the outer error,
// or sanitized copy for a root URL error with changed fields.
// Wrapper with another captured key → opaque boundary for classification and URL recovery.
// Wrapper of another goenvoy client (RedactionBoundary method) → opaque boundary: classification false; its Is, As, Timeout and Temporary not called.
// Forwarded identity search visits up to 4096 nodes and 64 joined errors.
// Stdlib classifier delegation (*net.OpError, *os.SyscallError, *fs.PathError, *url.Error) → followed during classification.
// Classification skips custom As methods and continues into their Unwrap tree.
// External Is method → called only when its Unwrap tree (64 nodes, read before the call) holds no package wrapper and is safe.
// External Timeout or Temporary method → false when its Unwrap tree (64 nodes, read before the call)
// holds a package wrapper or is unsafe.
// Classification reads each wrapper tree once within 64 nodes and classifies from that read, the starting wrapper included.
// A same-key wrapper entered during classification is read once the same way.
// Each classification charges the cause tree and each same-key wrapper tree once against 4096 reads.
// Each custom Is pre-check and each same-key wrapper entry charges the values its inspection examined (up to 65). Fewer than 65 units left → false.
// Classification dispatch pops at most 4096 slots on its own. A re-entered charged wrapper costs no read, but each pop counts.
// Unsafe tree → Timeout and Temporary false.
// Package-owned URL causes end classification → opaque cause false, classified cause captured values.
// Root and errors.As URL copies redact apikey query values before literal replacement and canonical check.
// URL copies keep nil causes. Typed-nil or unsafe causes become fixed opaque errors without classification.
// Root URL copy → one cause inspection. Unsafe first read → fixed opaque cause.
// Clean root whose Op, URL or cause field changes during inspection, or whose cause value is not comparable → fixed message.
// Unchanged root spends one of 64 reads: cause of 64 or more values read (typed-nil children included) → fixed message, no cause text read.
// Safe immediate cause implements Timeout or Temporary → read its tree and every same-key wrapper tree inside it once and use them for both classifications.
// The once-only read covers the copy's classification snapshot; the errors.As search that selects the URL error reads the cause separately.
//
// Contract limits
//
//   - Raw percent sign or backslash directly before key spelled across two or more escape layers.
//   - The check reads Unwrap results and checks Error text once per visited node, then re-reads
//     every recorded node's fields without calling error methods. A method can print the key or
//     write it into a recorded node's fields only on a later call, including after redaction returns.
//     The check cannot see that later text or write.
//   - Nested *url.Error with apikey value other than configured key.
//   - XML or HTML character references and escape schemes other than percent and backslash-u.
//   - For custom Is, Timeout or Temporary methods, the check uses the Unwrap tree read before the call.
//     A method that reaches a package wrapper through a later Unwrap read or another path enters that wrapper's
//     own bounded walk (4096 pops, 65-read floor). The return value is a boolean and carries no key text.
//   - Key that also occurs in key-independent text (REDACTED placeholder, fixed messages, Go-syntax
//     type names, field names or pointer addresses) → that text stays because it carries no key-derived bytes.
//
// Usage:
//
//	c, err := mylar.New("http://localhost:8090", "your-api-key")
//	if err != nil {
//		log.Fatal(err)
//	}
//	comics, err := c.GetIndex(context.Background())
package mylar
