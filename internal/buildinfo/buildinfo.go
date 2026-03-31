// Package buildinfo holds variables set at build time via ldflags.
package buildinfo

// Variables set via -ldflags "-X ...". Defaults are for dev builds.
var (
	Version    = "dev"
	Commit     = "unknown"
	TrustAddr  = "localhost:50053"
	VersionURL = "https://sigil-trust.dev/dl/version"
)
