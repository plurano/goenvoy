// Package nzbhydra provides a client for the NZBHydra2 API.
//
// NZBHydra2 is a meta search application for NZB indexers that provides
// a Newznab-compatible search API plus statistics and history endpoints.
// Authentication uses an API key passed as a query parameter.
//
// Key detection decodes percent escapes, backslash escapes, and both together.
// It redacts on a key match, more than 16 new projections in a layer,
// or a new projection at the fourth layer.
// Error redaction scans up to 64 nodes for structural inspection and URL recovery.
// Errors that control their own formatting or expose the key in Go-syntax output are wrapped.
// Each forwarded identity or classification search visits up to 4096 nodes and 64 joined errors.
// A sanitized URL error copy preserves nil and typed-nil causes. It hides other causes
// and captures their timeout and temporary classification together within one such walk.
//
// Usage:
//
//	c, err := nzbhydra.New("http://localhost:5076", "your-api-key")
//	if err != nil {
//		log.Fatal(err)
//	}
//	results, err := c.Search(context.Background(), "ubuntu", nil)
package nzbhydra
