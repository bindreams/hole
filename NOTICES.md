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

## Licensing map

- Hole's own code (`crates/common`, `crates/bridge`, `crates/hole`,
  `crates/dump`, `crates/dump-macros`, `crates/handle-holders`,
  `crates/tun-engine`, `crates/tun-engine-macros`, `xtask`, `xtask-lib`)
  is licensed under GPL-3.0-or-later; see `LICENSE.md` at the repo root.
- Ex-Galoshes code (`crates/garter`, `crates/garter-bin`,
  `crates/galoshes`, `crates/mock-plugin`) is licensed under Apache-2.0;
  see `crates/galoshes/LICENSE.md`.

The combined binary distributions produced by this workspace (`hole.exe`,
`hole.msi`, bundled `galoshes.exe`, and any future binaries) are distributed
as a whole under GPL-3.0-or-later, per Apache-2.0 → GPL-3.0 one-way
compatibility. The ex-Galoshes crates remain individually available under
Apache-2.0 for any downstream consumer who pulls them out of this
monorepo.

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
