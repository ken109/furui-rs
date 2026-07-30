pub use bind::*;
pub use connect::*;
pub use egress::*;
pub use ingress::*;

mod bind;
mod connect;
mod egress;
mod ingress;

#[cfg(feature = "user")]
mod common {
    use aya_ebpf::cty::c_char;

    pub(crate) fn u8_array_to_str<const N: usize>(array: [u8; N]) -> String {
        array
            .iter()
            .map(|&s| s as char)
            .collect::<String>()
            .split('\0')
            .next()
            .unwrap_or("")
            .to_string()
    }

    pub(crate) fn c_char_array_to_str<const N: usize>(array: [c_char; N]) -> String {
        array
            .iter()
            // `c_char` is unsigned on aarch64 and signed on x86_64, so this
            // cast is a no-op on one target and load-bearing on the other.
            .map(|&s| {
                #[allow(clippy::unnecessary_cast)]
                let byte = s as u8;
                byte as char
            })
            .collect::<String>()
            .split('\0')
            .next()
            .unwrap_or("")
            .to_string()
    }
}
