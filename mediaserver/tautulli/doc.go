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
// Key detection matches literal, percent-encoded, or backslash-u key bytes at each offset
// in input and in percent-only, backslash-only, and mixed decode projections.
// It redacts on a key match, more than 16 new projections in a layer,
// or a new projection at the fourth layer.
// Error redaction scans up to 64 nodes for structural inspection and URL recovery.
// Errors with custom formatting or As methods, or with exposed keys in Go-syntax output, are wrapped.
// Each forwarded identity or classification search visits up to 4096 nodes and 64 joined errors.
// Root and errors.As URL copies parse and redact apikey query values before literal key replacement
// and canonical check. Copies preserve nil and typed-nil causes and hide other causes.
// Immediate cause implements Timeout or Temporary → both classifications captured within one such walk.
// Contract limits — Raw percent sign or backslash directly before key spelled across two or more escape layers, typed-nil causes below immediate cause classify false, %#v inherits fmt recursion on self-referential values, formatting code emits key only on later call, nested *url.Error with apikey value other than configured key.
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
