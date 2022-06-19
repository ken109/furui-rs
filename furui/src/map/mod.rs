use aya::Bpf;

pub use container::ContainerMap;

mod container;

pub struct Maps<'a> {
    pub container: ContainerMap<'a>,
}

impl Maps<'_> {
    pub fn new(bpf: &mut Bpf) -> Maps {
        Maps {
            container: ContainerMap::new(bpf),
        }
    }
}
