use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

#[derive(Parser)]
#[command(name = "cargo-wix", bin_name = "cargo")]
pub(crate) struct Cargo {
    #[command(subcommand)]
    pub command: CargoSubcommand,
}

#[derive(Subcommand)]
pub(crate) enum CargoSubcommand {
    /// Build a Windows MSI installer using WiX Toolset
    Wix(WixArgs),
}

#[derive(Args)]
pub(crate) struct WixArgs {
    /// Path to the .wxs source file (overrides Cargo.toml)
    #[arg(long)]
    pub wxs: Option<PathBuf>,

    /// Output MSI path (overrides Cargo.toml)
    #[arg(long)]
    pub output: Option<PathBuf>,

    /// Skip the `before` hook
    #[arg(long)]
    pub skip_before: bool,

    /// Skip the `after` hook
    #[arg(long)]
    pub skip_after: bool,

    /// Additional bindpath: NAME=PATH (can be repeated)
    #[arg(long = "bindpath", value_name = "NAME=PATH")]
    pub bindpaths: Vec<String>,

    /// Additional WiX define: KEY=VALUE (can be repeated)
    #[arg(short = 'd', long = "define", value_name = "KEY=VALUE")]
    pub defines: Vec<String>,
}

#[cfg(test)]
#[path = "cli_tests.rs"]
mod cli_tests;
