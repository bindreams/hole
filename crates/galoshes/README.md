# galoshes

galoshes is a [SIP003](https://shadowsocks.org/doc/sip003.html) plugin for Shadowsocks that carries UDP as well as TCP.
It is [Hole](https://github.com/bindreams/hole)'s UDP-capable plugin. It puts every TCP connection and every UDP
exchange from the client on its own numbered stream inside one connection to the server, using the
[yamux](https://github.com/hashicorp/yamux/blob/master/spec.md) multiplexing protocol, and sends that one connection
through an [ex-ray](https://github.com/bindreams/hole/tree/main/crates/ex-ray) that is embedded in the galoshes binary
and runs as a child process. To the network, that connection looks the way an ex-ray connection does.

## Who it is for

People who run a Shadowsocks server and want a Hole client to reach it over UDP too: games, voice and video calls, and
anything else that is not plain TCP. If you only need TCP, or your server already runs a stock `v2ray-plugin`, use
ex-ray instead.

If you use the Hole app, you already have galoshes: Hole ships it, and a config that names `galoshes` as its plugin
uses it.

The server needs galoshes too. A stock plugin does not know the multiplexing layer, so it cannot talk to one.

## Install

Download the binary for your platform from a release tagged `releases/galoshes/v<version>` on the
[releases page](https://github.com/bindreams/hole/releases). Releases cover Windows, macOS and Linux, each on amd64 and
arm64, and the file is named `galoshes-<version>-<os>-<arch>`, where `<os>` is `windows`, `darwin` or `linux` and
`<arch>` is `amd64` or `arm64` (`.exe` on Windows). ex-ray is inside it, so there is
nothing else to install. galoshes is not published to crates.io.

## Use

You do not run galoshes by hand. A Shadowsocks client or server starts it as its plugin with the SIP003 environment
(`SS_LOCAL_HOST`, `SS_LOCAL_PORT`, `SS_REMOTE_HOST`, `SS_REMOTE_PORT` and `SS_PLUGIN_OPTIONS`), and it runs as the server
end when the options contain `server`. Both ends are given options in `SS_PLUGIN_OPTIONS`, separated by semicolons:

```text
tls;host=example.com;path=/ws
```

- Every option is handed to the embedded ex-ray, so ex-ray's options (`tls`, `host`, `path`, `ech` and the rest) work
  here. See the [ex-ray README](https://github.com/bindreams/hole/blob/main/crates/ex-ray/README.md).
- galoshes appends `mux=0` to them, because its own multiplexing already put every stream on one connection and ex-ray's
  would only add overhead. ex-ray reads the first value it finds for an option, so a `mux=` you write earlier wins. Both
  ends must agree: a client with `mux=0` cannot reach a server whose ex-ray expects `mux=1`.
- `udp_timeout=<seconds>` is galoshes' own option: how long the client keeps an idle UDP association before evicting it.
  The default is `DEFAULT_UDP_TIMEOUT` in [`yamux.rs`](src/yamux.rs). The value must be a positive whole number of
  seconds small enough to be a deadline from now. If any occurrence of the option is not, galoshes does not start,
  even when an earlier occurrence is valid.

galoshes speaks [sitrep](https://github.com/bindreams/hole/blob/main/crates/garter/SITREP.md) on its standard output to
report readiness, so its logs go to standard error.

If the connection to the server is reset, galoshes reconnects, and a keepalive catches a connection that goes silent
without a reset. A stream in flight when it reconnects is cut off.

## Documentation

- [Shadowsocks and its plugins](https://hole.readthedocs.io/en/latest/how-it-works/plugins.html) describes the
  multiplexing layer, its reconnection and its keepalive.
- [UDP: dropped, never bypassed](https://hole.readthedocs.io/en/latest/how-it-works/udp.html) explains what Hole does with
  UDP when the plugin in use cannot carry it.
- [What ships from the Hole repository](https://hole.readthedocs.io/en/latest/reference/distributions.html).

## License

Apache-2.0. See [`LICENSE`](LICENSE).
