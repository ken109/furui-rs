use std::process::Command;

pub use container::*;

mod container;

pub struct TestCase<'a> {
    pub commands: Vec<TestCommand<'a>>,
    pub in_container: bool,
}

impl TestCase<'_> {
    pub fn run(&self, container_id: String) {
        for command in &self.commands {
            command.run(container_id.clone(), self.in_container);
        }
    }
}

pub struct TestCommand<'a> {
    pub command: Vec<&'a str>,
    pub success: bool,
}

impl TestCommand<'_> {
    fn run(&self, container_id: String, in_container: bool) {
        let mut command: Vec<&str> = vec![];

        if in_container {
            command.append(&mut vec!["docker", "exec", container_id.as_str()])
        }

        command.append(&mut self.command.clone());

        let ret = Command::new(command[0])
            .args(&command[1..])
            .output()
            .unwrap();

        assert_eq!(ret.status.success(), self.success)
    }
}
