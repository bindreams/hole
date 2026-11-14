package main

// registerControlFunc is called whenever the vpn flag is true, which the
// `__android_vpn` option or the `-V` flag sets. It is empty: this build
// registers no socket-protection hook, so VPN mode does nothing
// (bindreams/hole#1336, open).
func registerControlFunc() {
}
