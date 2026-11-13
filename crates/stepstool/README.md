# stepstool

stepstool is a small Rust library for a program that runs as an ordinary user and needs exactly one child to run with
elevated rights. The parent never gains or sheds privilege; only the child it starts is elevated. It gives you sudo
credential priming and sudo-wrapped command construction on Unix, and elevation detection on Windows.

It is part of [Hole](https://github.com/bindreams/hole), a Shadowsocks client, where its callers are the developer
console (which runs the privileged bridge as one such child) and the `hole` binary (which asks whether it is already
privileged).

## Who it is for

Developers of tools that supervise a privileged helper: a launcher that starts a daemon under `sudo`, or a build or dev
script that must refuse to run from a non-elevated Windows shell.

It is not published to crates.io. Depend on it by path or by git from a checkout of this repository.

## Use

```toml
[dependencies]
stepstool = { git = "https://github.com/bindreams/hole" }
```

On Unix, prime sudo once so the spawn that follows does not stop at a password prompt, then wrap the child:

```rust,no_run
use std::process::Stdio;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    stepstool::prime_sudo()?;

    let mut child = stepstool::sudo_command("/usr/local/bin/daemon", &["MY_VAR"])
        .stdin(Stdio::null()) // an expired sudo timestamp then fails instead of hanging on a prompt
        .spawn()?;
    child.wait()?;
    Ok(())
}
```

`prime_sudo` checks for cached credentials and, when there are none, runs `sudo -v` so sudo asks for the password on the
terminal. `sudo_command` builds a `Command` that runs `program` under sudo and keeps the listed environment variables
through sudo's scrub; pass an absolute path, since sudo's `secure_path` ignores the caller's `PATH`. `preserve_env_arg` builds just the
`--preserve-env=` argument, for callers that assemble the sudo command line themselves.

On Windows, `is_elevated` reports whether the process token is elevated, and `require_elevated` fails with `NotElevated`
when it is not. `is_privileged` answers the same question on every platform: root on Unix, an elevated token on Windows.

## What it leaves out

There is no self-elevation on Windows (`runas`) and no de-elevation. On Windows the model is that the user starts an
elevated shell and its children inherit the token.

## License

Apache-2.0. See [`LICENSE`](LICENSE).
