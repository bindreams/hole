use clap::Parser;

use super::*;

fn parse(args: &[&str]) -> WixArgs {
    let mut full_args = vec!["cargo", "wix"];
    full_args.extend_from_slice(args);
    let cargo = Cargo::parse_from(full_args);
    let CargoSubcommand::Wix(wix_args) = cargo.command;
    wix_args
}

#[skuld::test]
fn parse_no_args() {
    let args = parse(&[]);
    assert!(args.wxs.is_none());
    assert!(args.output.is_none());
    assert!(!args.no_build);
    assert!(args.bindpaths.is_empty());
    assert!(args.defines.is_empty());
}

#[skuld::test]
fn parse_wxs_override() {
    let args = parse(&["--wxs", "custom/path.wxs"]);
    assert_eq!(args.wxs.as_deref(), Some(std::path::Path::new("custom/path.wxs")));
}

#[skuld::test]
fn parse_output_override() {
    let args = parse(&["--output", "build/out.msi"]);
    assert_eq!(args.output.as_deref(), Some(std::path::Path::new("build/out.msi")));
}

#[skuld::test]
fn parse_no_build() {
    let args = parse(&["--no-build"]);
    assert!(args.no_build);
}

#[skuld::test]
fn parse_defines() {
    let args = parse(&["-d", "Version=1.0", "-d", "Name=Test"]);
    assert_eq!(args.defines, vec!["Version=1.0", "Name=Test"]);
}

#[skuld::test]
fn parse_bindpaths() {
    let args = parse(&["--bindpath", "BinDir=/bin", "--bindpath", "DataDir=/data"]);
    assert_eq!(args.bindpaths, vec!["BinDir=/bin", "DataDir=/data"]);
}

#[skuld::test]
fn parse_all_options() {
    let args = parse(&[
        "--wxs",
        "my.wxs",
        "--output",
        "my.msi",
        "--no-build",
        "--bindpath",
        "B=P",
        "-d",
        "K=V",
    ]);
    assert_eq!(args.wxs.as_deref(), Some(std::path::Path::new("my.wxs")));
    assert_eq!(args.output.as_deref(), Some(std::path::Path::new("my.msi")));
    assert!(args.no_build);
    assert_eq!(args.bindpaths, vec!["B=P"]);
    assert_eq!(args.defines, vec!["K=V"]);
}
