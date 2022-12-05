use aya_tool::InputFile;
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
        "ipv6hdr",
        "tcphdr",
        "udphdr",
        "icmphdr",
        "icmp6hdr",
    ];

    let bindings = aya_tool::generate(
        InputFile::Btf(PathBuf::from("/sys/kernel/btf/vmlinux")),
        &names,
        &[],
    )?;

    let dest_path = "./furui-ebpf/src/vmlinux.rs";

    let mut vmlinux = File::create(dest_path)?;

    vmlinux.write_all(bindings.as_bytes())?;
    vmlinux.flush()?;

    let status = Command::new("rustfmt").args(&vec![dest_path]).status()?;

    assert!(status.success());

    Ok(())
}
