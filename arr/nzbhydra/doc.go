// Package nzbhydra provides a client for the NZBHydra2 API.
//
// NZBHydra2 is a meta search application for NZB indexers that provides
// a Newznab-compatible search API plus statistics and history endpoints.
// Authentication uses an API key passed as a query parameter.
//
// Key detection matches literal, percent, and backslash-u spellings per key byte at each offset.
// Percent-only, backslash-only, and mixed projections use the same matcher.
// Redaction triggers on key match, more than 16 new projections per layer,
// new projection at layer four, or retained projection bytes above 8x input size.
// Error redaction scans up to 64 nodes for structural inspection and URL recovery.
// Key in Error text, direct URL error fields, or reflected leaves → opaque wrapper.
// Reflection checks up to 1024 values per node and follows only the start pointer.
// Overflow or a nested fmt.Formatter or fmt.GoStringer → opaque wrapper.
// Custom formatting or As on an error node → opaque wrapper.
// Forwarded identity or classification search visits up to 4096 nodes and 64 joined errors.
// Root and errors.As URL copies redact apikey query values before literal replacement and canonical check.
// URL copies keep nil causes. Typed-nil or unsafe causes become fixed opaque errors without classification.
// Safe immediate cause implements Timeout or Temporary → both classifications captured in one walk.
//
// Contract limits
//
//   - Raw percent sign or backslash directly before key spelled across two or more escape layers.
//   - Error method prints key only on later call.
//   - Nested *url.Error with apikey value other than configured key.
//
// Usage:
//
//	c, err := nzbhydra.New("http://localhost:5076", "your-api-key")
//	if err != nil {
//		log.Fatal(err)
//	}
//	results, err := c.Search(context.Background(), "ubuntu", nil)
package nzbhydra
