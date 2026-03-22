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
    let (config, info) = config::load_config(None)?;

    // Resolve wxs path relative to crate manifest directory
    let wxs = args.wxs.unwrap_or_else(|| info.manifest_dir.join(&config.wxs));

    let mut builder = Builder::new(&wxs)
        .workspace_root(&info.workspace_root)
        .target_dir(&info.target_dir)
        .package_name(&info.name)
        .package_version(&info.version)
        .before(config.before)
        .after(config.after)
        .skip_before(args.skip_before)
        .skip_after(args.skip_after);

    if let Some(output) = args.output.or(config.output) {
        builder = builder.output(output);
    }

    // Bindpaths from config (resolved relative to workspace root)
    for (name, path) in config.bindpaths {
        let abs_path = info.workspace_root.join(&path);
        builder = builder.bindpath(name, abs_path);
    }

    // Defines from config, then CLI overrides
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

    // CLI bindpaths (added to config bindpaths)
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
