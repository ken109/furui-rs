use std::{env, path::PathBuf};

use anyhow::Context as _;

fn main() -> anyhow::Result<()> {
    // gRPC client for the Kubernetes CRI runtime service.
    env::set_var("PROTOC", protobuf_src::protoc());
    tonic_prost_build::compile_protos("proto/v1.proto").context("failed to compile protos")?;

    // This crate has a runtime dependency on the BPF object produced by
    // `furui-ebpf`, which only builds for `bpf{el,eb}-unknown-none` on nightly.
    // `aya_build` shells out to a second cargo invocation for it and drops the
    // resulting object in `OUT_DIR`, where `src/bpf/loader.rs` picks it up with
    // `include_bytes_aligned!`.
    //
    // This would be better expressed as an artifact dependency, but
    // https://github.com/rust-lang/cargo/issues/12375 prevents that for now.
    let ebpf_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .context("furui is not a workspace member")?
        .join("furui-ebpf");
    let ebpf_dir = ebpf_dir.to_str().context("furui-ebpf path is not UTF-8")?;

    aya_build::build_ebpf(
        [aya_build::Package {
            name: "furui-ebpf",
            root_dir: ebpf_dir,
            ..Default::default()
        }],
        aya_build::Toolchain::default(),
    )
}
