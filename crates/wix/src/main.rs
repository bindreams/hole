mod cli;

use clap::Parser;

use cargo_wix::config;
use cargo_wix::Builder;

use cli::{Cargo, CargoSubcommand};

fn main() {
    let Cargo {
        command: CargoSubcommand::Wix(args),
    } = Cargo::parse();

    if let Err(e) = run(args) {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn run(args: cli::WixArgs) -> cargo_wix::error::Result<()> {
    // Load config from Cargo.toml
    let (config, info) = config::load_config(None)?;

    // CLI overrides
    let wxs = args.wxs.unwrap_or(config.wxs);
    let build_first = if args.no_build { false } else { config.build };

    // Detect target triple from current platform
    let target_triple = format!("{}-pc-windows-msvc", std::env::consts::ARCH);

    let mut builder = Builder::new(&wxs)
        .build_first(build_first)
        .workspace_root(&info.workspace_root)
        .target_dir(info.target_dir.join("release"))
        .target_triple(&target_triple)
        .files(config.files);

    if let Some(output) = args.output.or(config.output) {
        builder = builder.output(output);
    }

    // Merge defines: config first, then CLI overrides
    for (k, v) in config.defines {
        builder = builder.define(k, v);
    }
    for def in &args.defines {
        if let Some((k, v)) = def.split_once('=') {
            builder = builder.define(k, v);
        } else {
            return Err(cargo_wix::Error::Config(format!(
                "invalid define (expected KEY=VALUE): {def}"
            )));
        }
    }

    // CLI bindpaths (added to any staged bindpaths)
    for bp in &args.bindpaths {
        if let Some((name, path)) = bp.split_once('=') {
            builder = builder.bindpath(name, path);
        } else {
            return Err(cargo_wix::Error::Config(format!(
                "invalid bindpath (expected NAME=PATH): {bp}"
            )));
        }
    }

    let output = builder.build()?;
    eprintln!("Installer built: {}", output.display());

    Ok(())
}
