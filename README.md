# furui

Communication control of the container runtime environment (now only docker) is
performed using eBPF.

## Prerequisites

furui builds and runs on Linux only, on a kernel with BTF
(`CONFIG_DEBUG_INFO_BTF`, i.e. `/sys/kernel/btf/vmlinux` exists). On macOS or
Windows, use a Linux VM.

1. A stable and a nightly Rust toolchain. `furui-ebpf` pins nightly through its
   `rust-toolchain.toml`, and `rustfmt.toml` uses unstable options:

   ```bash
   rustup toolchain install stable
   rustup toolchain install nightly --component rust-src
   ```

1. LLVM and a C/C++ toolchain. `bpf-linker` links against the system LLVM, and
   `protobuf-src` builds protoc from source:

   ```bash
   sudo apt install llvm-19-dev libpolly-19-dev clang-19 cmake build-essential
   export PATH=/usr/lib/llvm-19/bin:$PATH
   ```

1. The eBPF build tools:

   ```bash
   cargo install bpf-linker
   cargo install bindgen-cli
   cargo install aya-tool --git https://github.com/aya-rs/aya.git
   ```

1. Kernel bindings, generated from the running kernel's BTF:

   ```bash
   cargo xtask codegen
   ```

   This writes `furui-ebpf/src/vmlinux.rs`, which is not checked in. Re-run it
   after changing which kernel types `furui-ebpf` uses; that list lives in
   `xtask/src/main.rs`.

## Build

```bash
cargo build
```

`furui`'s build script compiles `furui-ebpf` for `bpf{el,eb}-unknown-none` and
embeds the resulting object, so there is no separate eBPF build step. Add
`--release` for a release build.

## Run

furui attaches kprobes and tc classifiers, so it needs root:

```bash
cargo xtask run -- example/nginx.yaml --log-level=info
```

Or run the binary directly:

```bash
sudo ./target/debug/furui example/nginx.yaml --log-level=info
```

See `furui --help` for the full set of options, and `example/` for policy files.

## Test

```bash
cargo test
```

Tests that need root, docker or a live kernel are marked `#[ignore]`; run them
with `cargo test -- --ignored` on a machine where that is safe.
