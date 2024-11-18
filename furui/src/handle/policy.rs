use std::{ops::Deref, path::PathBuf, sync::Arc, time::Duration};

use tokio::{sync::Mutex, task, time};
use tracing::info;

use crate::{domain::Policies, Containers, Maps, ParsePolicies};

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
                Ok(parsed_policies) => parsed_policies
                    .to_policies(containers.clone())
                    .await
                    .unwrap(),
                Err(_) => Arc::new(Mutex::new(Policies::default())),
            };

            if policies.lock().await.deref() != now_policies.lock().await.deref() {
                let _ = maps.policy.remove().await;

                policies.lock().await.policies = now_policies.lock().await.policies.clone();

                let _ = maps.policy.save(policies.clone()).await;

                info!("policy updated.");
            }
        }
    });

    Ok(())
}
