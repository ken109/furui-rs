use std::{ops::Deref, path::PathBuf, sync::Arc, time::Duration};

use tokio::{sync::RwLock, task, time};
use tracing::info;

use crate::{
    bpf::Maps,
    domain::{Containers, Policies},
    policy::ParsePolicies,
};

pub fn watch_file(
    policy_path: PathBuf,
    maps: Arc<Maps>,
    policies: Arc<RwLock<Policies>>,
    containers: Arc<RwLock<Containers>>,
) -> anyhow::Result<()> {
    task::spawn(async move {
        loop {
            time::sleep(Duration::from_secs(1)).await;

            let now_policies = match ParsePolicies::new(policy_path.clone()) {
                Ok(parsed_policies) => parsed_policies
                    .to_policies(containers.clone())
                    .await
                    .unwrap(),
                Err(_) => Arc::new(RwLock::new(Policies::default())),
            };

            if policies.read().await.deref() != now_policies.read().await.deref() {
                let _ = maps.policy.remove().await;

                policies.write().await.policies = now_policies.read().await.policies.clone();

                let _ = maps.policy.save(policies.clone()).await;

                info!("policy updated.");
            }
        }
    });

    Ok(())
}
