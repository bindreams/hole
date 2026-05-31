# ex-ray

ex-ray is a first-party SIP003 shadowsocks plugin built on
[v2ray-core](https://github.com/v2fly/v2ray-core). It builds the same
v2ray-core data-plane configuration that
[`shadowsocks/v2ray-plugin`](https://github.com/shadowsocks/v2ray-plugin)
builds, so it is **wire-compatible** with stock v2ray-plugin servers and
clients: a Hole client running ex-ray talks to a server running stock
v2ray-plugin, and vice versa.

ex-ray is **not** the upstream `shadowsocks/v2ray-plugin` project. It is
our own module, maintained in this repository. That means it can have
bugs the upstream project does not (and can fix bugs the upstream project
has). Its config-building construction is derived from
`shadowsocks/v2ray-plugin` (MIT-licensed); see the root
[`NOTICES.md`](../../NOTICES.md) for attribution.

ex-ray exists to give Hole a plugin it fully controls: it speaks a "sitrep"
control protocol on stdout (see [`../garter/SITREP.md`](../garter/SITREP.md))
and forces all v2ray-core logs to stderr.

## Build

```sh
go build ./...
```

## License

Apache-2.0. See [`LICENSE`](LICENSE).
