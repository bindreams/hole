# Notices

This product incorporates code from the Galoshes project
(formerly hosted at https://github.com/bindreams/galoshes, now merged
into this repository under `crates/{garter,garter-bin,galoshes,mock-plugin}`),
originally licensed under the Apache License, Version 2.0.

Copyright © 2025-2026 Anna Zhukova.

Licensed under the Apache License, Version 2.0 (the "License"); you may
not use the ex-Galoshes portions of this repository except in compliance
with the License. You may obtain a copy of the License at

```
http://www.apache.org/licenses/LICENSE-2.0
```

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
License for the specific language governing permissions and limitations
under the License.

The full Apache-2.0 license text accompanies the ex-Galoshes crates at
`crates/galoshes/LICENSE.md`.

## ex-ray (`crates/ex-ray`)

`crates/ex-ray` is a first-party SIP003 shadowsocks plugin built on
[v2ray-core](https://github.com/v2fly/v2ray-core). Its code is licensed
under the Apache License, Version 2.0; the full text accompanies it at
`crates/ex-ray/LICENSE`.

Copyright © 2025-2026 Anna Zhukova.

ex-ray's config-building construction is **derived from**
[`shadowsocks/v2ray-plugin`](https://github.com/shadowsocks/v2ray-plugin),
which is licensed under the MIT License. The MIT license is
GPL-3.0-compatible.

```
MIT License

Copyright (c) 2019 by Max Lv <max.c.lv@gmail.com>
Copyright (C) 2019 by Mygod Studio <contact-v2ray-plugin@mygod.be>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

ex-ray depends on `github.com/v2fly/v2ray-core/v5`, which is licensed
under the MIT License. The MIT license is GPL-3.0-compatible. v2ray-core
is statically linked into the ex-ray binary, so its bytes are covered by
the combined-distribution terms below.

```
The MIT License (MIT)

Copyright (c) 2015-2025 V2Fly Community

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## Licensing map

- Hole's own code (`crates/common`, `crates/bridge`, `crates/hole`,
  `crates/dump`, `crates/dump-macros`, `crates/handle-holders`,
  `crates/tun-engine`, `crates/tun-engine-macros`, `xtask`, `xtask-lib`)
  is licensed under GPL-3.0-or-later; see `LICENSE.md` at the repo root.
- Ex-Galoshes code (`crates/garter`, `crates/garter-bin`,
  `crates/galoshes`, `crates/mock-plugin`) is licensed under Apache-2.0;
  see `crates/galoshes/LICENSE.md`.
- ex-ray (`crates/ex-ray`) is licensed under Apache-2.0; see
  `crates/ex-ray/LICENSE`. It is derived from `shadowsocks/v2ray-plugin`
  (MIT) and depends on `v2fly/v2ray-core` (MIT), both attributed above.

The combined binary distributions produced by this workspace (`hole.exe`,
`hole.msi`, bundled `galoshes.exe`, and any future binaries) are distributed
as a whole under GPL-3.0-or-later, per Apache-2.0 → GPL-3.0 one-way
compatibility. The ex-Galoshes crates remain individually available under
Apache-2.0 for any downstream consumer who pulls them out of this
monorepo.

## Native-crash observability dependencies (`crates/tombstone`)

The `tombstone` crate (`crates/tombstone`) is first-party, licensed under
the Apache License, Version 2.0 — deliberately permissive so the standalone
`galoshes` binary can depend on it without acquiring a GPL edge. Copyright ©
2025-2026 Anna Zhukova.

`tombstone` links the following third-party crates, all dual-licensed
MIT OR Apache-2.0 (both GPL-3.0-compatible):

- [`crash-handler`](https://github.com/EmbarkStudios/crash-handling) and its
  companion `crash-context` — the native-fault catcher (installs
  `SetUnhandledExceptionFilter` + vectored handlers on Windows, task-level
  Mach exception ports on macOS, POSIX signal handlers on Linux). Always
  linked (Windows / macOS / Linux all first-tier).
- [`minidump-writer`](https://github.com/rust-minidump/minidump-writer) — the
  dev-only `.dmp` writer, linked **only** under the non-default `crash-dumps`
  cargo feature. It is absent from all release artifacts (MSI / DMG /
  standalone galoshes), so a memory-bearing minidump — which for a privacy
  VPN would hold keys and user traffic — is never producible by shipped
  binaries.
- [`sadness-generator`](https://github.com/EmbarkStudios/crash-handling) — a
  dev-dependency only (deterministic fault triggers used by the
  per-fault-class tests). Never linked into any shipped binary.

These crates' bytes, where linked (`crash-handler`/`crash-context` always;
`minidump-writer` in dev builds), are covered by the combined-distribution
GPL-3.0 terms above per MIT/Apache → GPL one-way compatibility.

## Bundled third-party UI assets

The Hole GUI bundles country-flag SVGs from
[`flag-icons`](https://github.com/lipis/flag-icons), licensed under
the MIT License. Both the CSS rules and the SVG files (under
`ui/flags/{1x1,4x3}/*.svg` in the unpacked `flag-icons` npm package) are
incorporated into the built `ui/dist/` bundle that ships inside the
Tauri webview asset payload. The MIT license is GPL-3.0-compatible.

```
The MIT License (MIT)

Copyright (c) 2013 Panayiotis Lipiridis

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
```
