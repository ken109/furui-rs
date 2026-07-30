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

#[cfg(test)]
mod tests {
    use furui_common::TASK_COMM_LEN;

    use super::*;

    #[test]
    fn pads_a_short_string_with_zeroes() {
        let bytes: [u8; TASK_COMM_LEN] = string_to_u8_bytes("nginx".to_string());

        assert_eq!(&bytes[..5], b"nginx");
        assert!(bytes[5..].iter().all(|&b| b == 0));
    }

    #[test]
    fn truncates_a_string_that_does_not_fit() {
        // The kernel's own limit; a longer comm simply cannot be represented.
        let bytes: [u8; 4] = string_to_u8_bytes("nginx".to_string());

        assert_eq!(&bytes, b"ngin");
    }

    #[test]
    fn an_empty_string_is_all_zeroes() {
        let bytes: [u8; TASK_COMM_LEN] = string_to_u8_bytes(String::new());

        assert_eq!(bytes, [0; TASK_COMM_LEN]);
    }

    #[test]
    fn c_char_conversion_matches_the_byte_conversion() {
        let bytes: [u8; 12] = string_to_u8_bytes("abcdef123456".to_string());
        let chars: [c_char; 12] = string_to_c_char_bytes("abcdef123456".to_string());

        for (byte, ch) in bytes.iter().zip(chars.iter()) {
            // `c_char` is unsigned on aarch64, signed on x86_64.
            #[allow(clippy::unnecessary_cast)]
            let ch = *ch as u8;
            assert_eq!(*byte, ch);
        }
    }
}
