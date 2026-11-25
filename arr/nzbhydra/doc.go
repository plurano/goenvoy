// Package nzbhydra provides a client for the NZBHydra2 API.
//
// NZBHydra2 is a meta search application for NZB indexers that provides
// a Newznab-compatible search API plus statistics and history endpoints.
// Authentication uses an API key passed as a query parameter.
//
// Error redaction scans up to 64 nodes each for URL-error recovery and structural inspection, and forwarding visits up to 64 joined errors and 4096 nodes.
// Error trees with custom formatters expose only their sanitized message.
// Sanitized URL error copies classify timeouts and temporary failures using the original immediate cause's methods.
// Nil and typed-nil URL causes become nil in the copy.
//
// Usage:
//
//	c, err := nzbhydra.New("http://localhost:5076", "your-api-key")
//	if err != nil {
//		log.Fatal(err)
//	}
//	results, err := c.Search(context.Background(), "ubuntu", nil)
package nzbhydra
