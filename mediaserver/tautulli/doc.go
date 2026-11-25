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
// Key detection decodes percent escapes, backslash escapes, and both together.
// It redacts on a key match, more than 16 new projections in a layer,
// or a new projection at the fourth layer.
// Error redaction scans up to 64 nodes for structural inspection and URL recovery.
// Errors that control their own formatting or expose the key in Go-syntax output are wrapped.
// Each forwarded identity or classification search visits up to 4096 nodes and 64 joined errors.
// A sanitized URL error copy preserves nil and typed-nil causes. It hides other causes
// and captures their timeout and temporary classification together within one such walk.
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
