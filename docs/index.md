# Hole

Hole is a Shadowsocks client for macOS and Windows. It routes traffic through a
TUN interface, so every application on the machine goes through the tunnel —
including the ones that ignore system proxy settings — and carries DNS through
the tunnel too. Traffic is camouflaged as WebSocket and TLS by the bundled
first-party `ex-ray` plugin, or by `galoshes`, which adds UDP support.

```{note}
This documentation is not written yet. Only the site itself exists so far;
see [issue #849](https://github.com/bindreams/hole/issues/849) for progress.

In the meantime, the [README](https://github.com/bindreams/hole#readme) covers
installing and using Hole, and
[CONTRIBUTING.md](https://github.com/bindreams/hole/blob/main/CONTRIBUTING.md)
covers building and hacking on it.
```

Component versions: hole {{ hole_version }}, galoshes {{ galoshes_version }}, garter {{ garter_version }}, ex-ray {{ exray_version }}.

Hole is free software under the [GNU GPL version 3](license.md); the source
lives in the [GitHub repository](https://github.com/bindreams/hole).

```{toctree}
---
hidden:
---
License <license.md>
GitHub repository <https://github.com/bindreams/hole>
```
