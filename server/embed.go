// Package main provides embedded filesystem access for the React frontend.
// The web/dist directory is embedded at compile time so the server can serve
// the frontend without requiring external files.
package main

import "embed"

// WebDist embeds the compiled React frontend from web/dist.
// This allows the server binary to serve the UI without external file dependencies.
//
//go:embed web/dist
var WebDist embed.FS
