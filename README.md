# furui

Communication control of the container runtime environment(now only docker) is performed using eBPF.

## Prerequisites

1. Install a rust stable toolchain: `rustup install stable`
1. Install a rust nightly toolchain: `rustup install nightly`
1. Install LLVM
1. Install bpf-linker: `cargo install bpf-linker`
1. Install bpftool: `sudo apt install linux-tools-generic`
1. Install bindgen-cli: `cargo install bindgen-cli`
1. `cargo xtask aya-gen`

## Build eBPF

```bash
cargo xtask build-ebpf
```

To perform a release build you can use the `--release` flag.
You may also change the target architecture with the `--target` flag

## Build Userspace

```bash
cargo build
```

## Run

```bash
cargo xtask run -- example/nginx.yaml --log-level=info
```
