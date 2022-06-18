use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

pub fn aya_gen() -> anyhow::Result<()> {
    let dir = PathBuf::from("furui-ebpf");
    let args = vec![
        "btf-types",
        "task_struct",
        "sockaddr_in",
        "sockaddr_in6",
        "inet_sock",
    ];
    let output = Command::new("aya-gen")
        .current_dir(&dir)
        .args(&args)
        .output()
        .expect("failed to aya-gen");

    let output_string = String::from_utf8(output.stdout)?;

    let mut vmlinux = File::create("./furui-ebpf/src/vmlinux.rs")?;

    vmlinux.write_all(output_string.as_bytes())?;
    vmlinux.flush()?;

    let status = Command::new("rustfmt")
        .current_dir(&dir)
        .args(&vec!["src/vmlinux.rs"])
        .status()
        .expect("failed to rustfmt");

    assert!(status.success());

    Ok(())
}
