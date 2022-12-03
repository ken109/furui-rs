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
    use aya_bpf_cty::c_char;

    pub(crate) fn u8_array_to_str<const N: usize>(array: [u8; N]) -> String {
        array
            .iter()
            .map(|&s| s as char)
            .collect::<String>()
            .split("\0")
            .nth(0)
            .unwrap_or("")
            .to_string()
    }

    pub(crate) fn c_char_array_to_str<const N: usize>(array: [c_char; N]) -> String {
        array
            .iter()
            .map(|&s| (s as u8) as char)
            .collect::<String>()
            .split("\0")
            .nth(0)
            .unwrap_or("")
            .to_string()
    }
}
