// Package tautulli provides a client for the Tautulli API.
//
// Tautulli (https://tautulli.com) is a monitoring and tracking tool for
// Plex Media Server. The API provides access to activity streams, watch
// history, library statistics, user analytics, and server information.
//
// # Authentication
//
// All requests require an API key, which can be found in
// Tautulli Settings → Web Interface → API key.
//
// Error redaction scans up to 64 nodes each for URL-error recovery and structural inspection, and forwarding visits up to 64 joined errors and 4096 nodes.
//
// # Usage
//
//	client, err := tautulli.New("http://localhost:8181", "your-api-key")
//	if err != nil {
//		log.Fatal(err)
//	}
//	activity, err := client.GetActivity(ctx)
//	if err != nil {
//		log.Fatal(err)
//	}
package tautulli
