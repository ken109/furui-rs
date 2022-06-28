use aya_bpf::bindings::TC_ACT_OK;
use aya_bpf::cty::c_long;
use aya_bpf::programs::SkBuffContext;

pub(crate) unsafe fn ipv4_icmp(_ctx: &SkBuffContext) -> Result<i32, c_long> {
    Ok(TC_ACT_OK)
}
