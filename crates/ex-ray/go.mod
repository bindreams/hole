module github.com/bindreams/hole/ex-ray

go 1.25.5

require (
	github.com/golang/protobuf v1.5.4
	github.com/v2fly/v2ray-core/v5 v5.51.2
	google.golang.org/protobuf v1.36.11
)

// v2ray-core is vendored in-tree (git-subrepo) so it can be patched for ECH
// robustness; this local copy is the build truth. See third_party/VENDORING.md.
replace github.com/v2fly/v2ray-core/v5 => ./third_party/v2ray-core

require (
	github.com/adrg/xdg v0.5.3 // indirect
	github.com/gorilla/websocket v1.5.3 // indirect
	github.com/miekg/dns v1.1.72 // indirect
	github.com/pires/go-proxyproto v0.12.0 // indirect
	github.com/quic-go/quic-go v0.59.1 // indirect
	golang.org/x/crypto v0.51.0 // indirect
	golang.org/x/exp v0.0.0-20241009180824-f66d83c29e7c // indirect
	golang.org/x/mod v0.35.0 // indirect
	golang.org/x/net v0.54.0 // indirect
	golang.org/x/sync v0.20.0 // indirect
	golang.org/x/sys v0.44.0 // indirect
	golang.org/x/text v0.37.0 // indirect
	golang.org/x/tools v0.44.0 // indirect
)
