# Contributing

This section is for people who build, change and test Hole. It starts from a clean machine and ends at a change you can
test and submit.

Hole is a Rust workspace with a Go plugin ({term}`ex-ray`) and a TypeScript front end. One task runner, `cargo xtask`,
drives the builds and the test runs.

## Start here

1. [Set up and build](setup.md): install the tools, then build and test once.
1. [The workspace](workspace.md): what each directory holds, and how {term}`galoshes` carries ex-ray.
1. [Development](development.md): run Hole from a checkout, with the bridge elevated and the front end hot-reloading.
1. [Testing](testing.md): run the tests, and the rules every test follows.
1. [Continuous integration](ci.md): what runs on a pull request, and what you can run locally.
1. [Commit messages](commit-messages.md): the format a PR title or commit subject must have.

Reference pages: [building in detail](build.md), [the installers](installers.md) and [the bridge and proxy
commands](bridge-cli.md).

Cutting a release, rolling one back, and the signing key are in [the maintainers' pages](maintainers/index.md).

How Hole is put together is in the [architecture overview](architecture/overview.md), which links the pages on the
layers, the TUN device, routing and [the kill switch](architecture/kill-switch.md).
