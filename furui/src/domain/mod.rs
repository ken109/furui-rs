use aya_ebpf::cty::c_char;
pub use container::*;
pub use policy::*;
pub use process::*;

mod container;
mod policy;
mod process;

/// Copies `src` into a fixed-size buffer, zero-padding or truncating to `N`.
///
/// The eBPF maps are keyed by fixed-size byte arrays, so anything longer than
/// the key is silently cut; callers pass `TASK_COMM_LEN`/`CONTAINER_ID_LEN`,
/// which are the kernel's own limits for these values.
fn string_to_u8_bytes<const N: usize>(src: String) -> [u8; N] {
    let mut result = [0u8; N];

    for (slot, byte) in result.iter_mut().zip(src.bytes()) {
        *slot = byte;
    }

    result
}

/// As [`string_to_u8_bytes`], but for the `char` arrays the kernel uses.
fn string_to_c_char_bytes<const N: usize>(src: String) -> [c_char; N] {
    let mut result = [0 as c_char; N];

    for (slot, byte) in result.iter_mut().zip(src.bytes()) {
        *slot = byte as c_char;
    }

    result
}
