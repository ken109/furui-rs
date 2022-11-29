use std::path::PathBuf;

use furui;
use furui::{ContainerRuntime, LogFormat, LogLevel, Options};

use crate::common::{Container, TestCase, TestCommand};

mod common;

#[tokio::test]
async fn nginx() {
    let opt = Options {
        container_engine: ContainerRuntime::Docker,
        policy_path: PathBuf::from("../example/nginx.yaml"),
        log_level: LogLevel::Warn,
        log_fmt: LogFormat::Text,
    };

    unsafe { furui::start(opt).await.unwrap() };

    let nginx_test = Container::new("nginx_test", "nginx").await;

    let test_cases = vec![
        TestCase {
            commands: vec![
                TestCommand {
                    command: vec!["curl", "-m", "1", &nginx_test.ipv4_url.as_str()],
                    success: true,
                },
                TestCommand {
                    command: vec!["curl", "-m", "1", &nginx_test.ipv6_url.as_str()],
                    success: true,
                },
            ],
            in_container: false,
        },
        TestCase {
            commands: vec![TestCommand {
                command: vec!["curl", "-m", "1", "https://httpbin.org/ip"],
                success: false,
            }],
            in_container: true,
        },
    ];

    for test_case in test_cases {
        test_case.run(nginx_test.id.clone());
    }

    nginx_test.remove().await;
}
