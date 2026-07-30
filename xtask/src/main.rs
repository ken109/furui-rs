//! Repository automation tasks.
//!
//! Run via the workspace alias: `cargo xtask <command>`.

use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{bail, Context as _};
use clap::{Parser, Subcommand};

/// Kernel types that `furui-ebpf` reads through `crate::vmlinux`.
///
/// Keep this in sync with the `use crate::vmlinux::…` statements in
/// `furui-ebpf/src/`; `xtask codegen` verifies that every name here ends up in
/// the generated bindings, so a missing entry fails loudly instead of relying
/// on `aya-tool` happening to pull the type in transitively.
const VMLINUX_TYPES: &[&str] = &[
    "ethhdr",
    "flowi4",
    "flowi6",
    "icmphdr",
    "inet_sock",
    "iphdr",
    "ipv6hdr",
    "sock",
    "sockaddr_in",
    "sockaddr_in6",
    "socket",
    "task_struct",
    "tcphdr",
    "udphdr",
];

const VMLINUX_OUT: &str = "furui-ebpf/src/vmlinux.rs";

#[derive(Parser)]
#[command(about = "furui repository tasks")]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Regenerate `furui-ebpf/src/vmlinux.rs` from the running kernel's BTF.
    Codegen,
    /// Build the userspace binary and run it as root.
    Run {
        /// Build in release mode.
        #[arg(long)]
        release: bool,
        /// Arguments forwarded to the `furui` binary.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
}

fn main() -> anyhow::Result<()> {
    match Cli::parse().command {
        Cmd::Codegen => codegen(),
        Cmd::Run { release, args } => run(release, &args),
    }
}

fn workspace_root() -> PathBuf {
    // xtask lives at `<root>/xtask`, so its manifest dir's parent is the root.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask is a workspace member")
        .to_path_buf()
}

fn codegen() -> anyhow::Result<()> {
    let root = workspace_root();
    let out = root.join(VMLINUX_OUT);

    let btf = Path::new("/sys/kernel/btf/vmlinux");
    if !btf.exists() {
        bail!(
            "{} not found: `xtask codegen` needs a Linux host with BTF enabled \
             (CONFIG_DEBUG_INFO_BTF)",
            btf.display()
        );
    }

    let output = Command::new("aya-tool")
        .arg("generate")
        .args(VMLINUX_TYPES)
        .output()
        .context("failed to run `aya-tool`; install it with `cargo install aya-tool`")?;

    if !output.status.success() {
        bail!(
            "aya-tool generate failed ({}):\n{}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let bindings = String::from_utf8(output.stdout).context("aya-tool emitted non-UTF-8 output")?;

    // `aya-tool` resolves types transitively, so a name we asked for can still
    // go missing if the kernel renamed or removed it. Catch that here rather
    // than in a confusing `furui-ebpf` compile error.
    let missing: Vec<_> = VMLINUX_TYPES
        .iter()
        .filter(|ty| !defines_type(&bindings, ty))
        .collect();
    if !missing.is_empty() {
        bail!("aya-tool did not emit bindings for: {missing:?}");
    }

    if let Some(parent) = out.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&out, bindings).with_context(|| format!("failed to write {}", out.display()))?;

    println!("wrote {} ({} types)", out.display(), VMLINUX_TYPES.len());
    Ok(())
}

/// Whether `bindings` contains a `struct`/`union` item named `ty`.
fn defines_type(bindings: &str, ty: &str) -> bool {
    bindings.lines().any(|line| {
        let line = line.trim_start();
        for kw in ["pub struct ", "pub union ", "pub type "] {
            if let Some(rest) = line.strip_prefix(kw) {
                let name = rest
                    .split(|c: char| !c.is_alphanumeric() && c != '_')
                    .next()
                    .unwrap_or_default();
                if name == ty {
                    return true;
                }
            }
        }
        false
    })
}

fn run(release: bool, args: &[String]) -> anyhow::Result<()> {
    let root = workspace_root();

    let mut build = Command::new("cargo");
    build
        .current_dir(&root)
        .args(["build", "--package", "furui"]);
    if release {
        build.arg("--release");
    }
    let status = build.status().context("failed to run cargo build")?;
    if !status.success() {
        bail!("cargo build failed: {status}");
    }

    let profile = if release { "release" } else { "debug" };
    let bin = root.join("target").join(profile).join("furui");

    // furui attaches kprobes and tc classifiers, so it needs root.
    let status = Command::new("sudo")
        .arg("-E")
        .arg(&bin)
        .args(args)
        .status()
        .with_context(|| format!("failed to run {}", bin.display()))?;
    if !status.success() {
        bail!("furui exited with {status}");
    }
    Ok(())
}
