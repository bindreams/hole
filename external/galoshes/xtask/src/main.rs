mod v2ray_plugin;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "xtask", about = "Build tasks for the galoshes workspace")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Build v2ray-plugin from vendored Go source
    V2rayPlugin {
        /// Target triple (defaults to host target)
        #[arg(long)]
        target: Option<String>,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::V2rayPlugin { target } => v2ray_plugin::build(target.as_deref()),
    }
}
