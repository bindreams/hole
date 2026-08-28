module github.com/bindreams/hole/ex-ray

go 1.25.5

// The Go pin, for every consumer at once: `go` itself honours this locally, so
// a bare `go build` cannot silently use whatever is first on PATH, and
// `actions/setup-go` prefers it over the `go` directive above, so CI and the
// released binary are built by the same release. Renovate never automerges
// this directive — see .github/renovate.json. setup-go reads this unless
// `GOTOOLCHAIN` is set to exactly `local` — presetting it to `local` in a
// workflow would silently drop CI back to the `go` directive's version.
toolchain go1.27.0

require (
	github.com/golang/protobuf v1.5.4
	github.com/v2fly/v2ray-core/v5 v5.52.0
	golang.org/x/sys v0.47.0
	google.golang.org/protobuf v1.36.12
)

// v2ray-core is vendored in-tree (git-subrepo) so it can be patched for ECH
// robustness; this local copy is the build truth. See third_party/VENDORING.md.
replace github.com/v2fly/v2ray-core/v5 => ./third_party/v2ray-core

// refraction-networking/utls is vendored in-tree (git-subrepo) and patched so an
// ECH-rejection retry verifies the outer public_name (not the concealed inner
// name); this local copy is the build truth. See third_party/VENDORING.md.
replace github.com/refraction-networking/utls => ./third_party/utls

require (
	github.com/adrg/xdg v0.5.3 // indirect
	github.com/andybalholm/brotli v1.0.6 // indirect
	github.com/gorilla/websocket v1.5.3 // indirect
	github.com/klauspost/compress v1.17.4 // indirect
	github.com/miekg/dns v1.1.72 // indirect
	github.com/mustafaturan/bus v1.0.2 // indirect
	github.com/pelletier/go-toml v1.9.5 // indirect
	github.com/pires/go-proxyproto v0.12.0 // indirect
	github.com/quic-go/quic-go v0.59.1 // indirect
	github.com/refraction-networking/utls v1.8.2 // indirect
	golang.org/x/crypto v0.53.0 // indirect
	golang.org/x/exp v0.0.0-20241009180824-f66d83c29e7c // indirect
	golang.org/x/mod v0.36.0 // indirect
	golang.org/x/net v0.56.0 // indirect
	golang.org/x/sync v0.21.0 // indirect
	golang.org/x/text v0.38.0 // indirect
	golang.org/x/tools v0.45.0 // indirect
)
