use std::ops::Deref;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Mutex;
use tokio::{task, time};
use tracing::info;

use crate::domain::Policies;
use crate::{Containers, Maps, ParsePolicies};

pub fn policy_events(
    policy_path: PathBuf,
    maps: Arc<Maps>,
    policies: Arc<Mutex<Policies>>,
    containers: Arc<Mutex<Containers>>,
) -> anyhow::Result<()> {
    task::spawn(async move {
        loop {
            time::sleep(Duration::from_secs(1)).await;

            let now_policies = match ParsePolicies::new(policy_path.clone()) {
                Ok(parsed_policies) => parsed_policies.to_domain(containers.clone()).await.unwrap(),
                Err(_) => Arc::new(Mutex::new(Policies::default())),
            };

            if policies.lock().await.deref() != now_policies.lock().await.deref() {
                unsafe {
                    let _ = maps.policy.remove().await;
                }

                policies.lock().await.policies = now_policies.lock().await.policies.clone();

                unsafe {
                    let _ = maps.policy.save(policies.clone()).await;
                }

                info!("policy updated.");
            }
        }
    });

    Ok(())
}
