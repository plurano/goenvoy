// Package mylar provides a client for the Mylar3 API.
//
// Mylar3 is an automated comic book downloader and manager.
// Authentication uses an API key passed as a query parameter.
//
// Error redaction scans up to 64 nodes each for URL-error recovery and structural inspection, and forwarding visits up to 64 joined errors and 4096 nodes.
//
// Usage:
//
//	c, err := mylar.New("http://localhost:8090", "your-api-key")
//	if err != nil {
//		log.Fatal(err)
//	}
//	comics, err := c.GetIndex(context.Background())
package mylar
