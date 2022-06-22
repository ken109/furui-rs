use aya_gen::InputFile;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

pub fn aya_gen() -> anyhow::Result<()> {
    let names = vec![
        "task_struct",
        "sockaddr_in",
        "sockaddr_in6",
        "inet_sock",
        "__sk_buff",
    ];

    let bindings = aya_gen::generate(
        InputFile::Btf(PathBuf::from("/sys/kernel/btf/vmlinux")),
        &names,
        &[],
    )?;

    let mut vmlinux = File::create("./furui-ebpf/src/vmlinux.rs")?;

    vmlinux.write_all(bindings.as_bytes())?;
    vmlinux.flush()?;

    let status = Command::new("rustfmt")
        .args(&vec!["./furui-ebpf/src/vmlinux.rs"])
        .status()?;

    assert!(status.success());

    Ok(())
}
