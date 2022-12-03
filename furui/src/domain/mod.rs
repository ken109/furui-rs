use aya_bpf_cty::c_char;

pub use container::*;
pub use policy::*;
pub use process::*;

mod container;
mod policy;
mod process;

fn string_to_u8_bytes<const N: usize>(src: String) -> [u8; N] {
    let mut result: [u8; N] = [0; N];

    let bytes = src.as_bytes();
    for i in 0..N {
        result[i] = *bytes.get(i).unwrap_or(&0) as u8;
    }

    result
}

fn string_to_c_char_bytes<const N: usize>(src: String) -> [c_char; N] {
    let mut result: [c_char; N] = [0; N];

    let bytes = src.as_bytes();
    for i in 0..N {
        result[i] = *bytes.get(i).unwrap_or(&0) as c_char;
    }

    result
}
