use profile_policy::{ExplicitOverlay, InputsOverlay, ManagedOverlay, NetworkOverlay};
use serde_json::{Value, json};
use std::{
    io,
    sync::{Arc, Mutex},
};
use xkeen_ui::configuration::{Activation, ActivationError, ConfigStore, Validator};

fn explicit() -> ExplicitOverlay {
    ExplicitOverlay {
        lan_ifname: "br-lan".into(),
        lan_ipv4: "192.0.2.1".parse().unwrap(),
        lan_scope: "192.0.2.0/24".into(),
        port: 7890,
        owner_id: "00000000-0000-4000-8000-000000000001".into(),
        generation: 1,
    }
}
fn gateway() -> NetworkOverlay {
    NetworkOverlay {
        lan_ifname: "br-lan".into(),
        lan_ipv4: "192.0.2.1".parse().unwrap(),
        selected_ipv4: "192.0.2.10".parse().unwrap(),
        tproxy_port: 7893,
        dns_port: 1053,
        nameservers: vec!["192.0.2.53".parse().unwrap()],
        bootstrap: vec!["192.0.2.53".parse().unwrap()],
        local_zones: vec!["+.lan".into()],
    }
}
struct Capture(Arc<Mutex<String>>);
impl Validator for Capture {
    fn validate(&self, config: &str) -> Result<(), ActivationError> {
        *self.0.lock().unwrap() = config.into();
        Ok(())
    }
}
#[test]
fn one_accepted_profile_has_independent_explicit_and_gateway_inputs() {
    let root = std::env::temp_dir().join(format!("inputs-{}", uuid::Uuid::new_v4()));
    let store = ConfigStore::new(&root).unwrap();
    let saved = store
        .save("config", "mode: rule\nproxies: []\nrules: ['MATCH,DIRECT']\n", None)
        .unwrap();
    let bytes = Arc::new(Mutex::new(String::new()));
    let mut activation = Activation::new(store, Capture(bytes.clone()), "a".repeat(64));
    activation.validate("config", &saved.revision).unwrap();
    let base = bytes.lock().unwrap().clone();
    for (e, g, mixed, tproxy, dns) in [
        (false, false, 0, 0, false),
        (true, false, 7890, 0, false),
        (false, true, 0, 7893, true),
        (true, true, 7890, 7893, true),
    ] {
        let inputs = InputsOverlay {
            explicit: e.then(explicit),
            gateway: g.then(gateway),
        };
        let combined = profile_policy::compose_inputs(&base, &[], &inputs).unwrap();
        let doc: Value = serde_json::from_str(&combined).unwrap();
        assert_eq!(doc["mixed-port"], mixed);
        assert_eq!(doc["tproxy-port"], tproxy);
        assert_eq!(doc["dns"]["enable"], dns);
        assert!(profile_policy::complete_for(
            &combined,
            &[],
            &ManagedOverlay::Composite(inputs.clone())
        ));
        let mut injected = doc.clone();
        injected["mixed-port"] = json!(8900);
        assert!(!profile_policy::complete_for(
            &injected.to_string(),
            &[],
            &ManagedOverlay::Composite(inputs)
        ));
    }
    let mut mismatch = explicit();
    mismatch.lan_ipv4 = "192.0.2.2".parse().unwrap();
    assert!(
        profile_policy::compose_inputs(
            &base,
            &[],
            &InputsOverlay {
                explicit: Some(mismatch),
                gateway: Some(gateway())
            }
        )
        .is_err()
    );
    std::fs::remove_dir_all(root).unwrap();
}
struct Guard {
    nft: Value,
    state: xkeenwrt_recovery::explicit::GuardState,
    writes: usize,
    applies: usize,
}
impl xkeenwrt_recovery::explicit::Adapter for Guard {
    fn read_nft(&mut self) -> io::Result<Vec<u8>> {
        Ok(self.nft.to_string().into_bytes())
    }
    fn apply_nft(&mut self, _: &str) -> io::Result<()> {
        self.applies += 1;
        Err(io::Error::other("unexpected mutation"))
    }
    fn load(&mut self) -> io::Result<xkeenwrt_recovery::explicit::GuardState> {
        Ok(self.state.clone())
    }
    fn persist(&mut self, s: &xkeenwrt_recovery::explicit::GuardState) -> io::Result<()> {
        self.writes += 1;
        self.state = s.clone();
        Ok(())
    }
}
#[test]
fn stable_explicit_guard_revalidates_without_flash_writes_and_never_claims_foreign_table() {
    use xkeenwrt_recovery::explicit::{self, GuardState};
    let e = explicit();
    let mut guard = Guard {
        nft: explicit::expected(&e).unwrap(),
        state: GuardState {
            current: Some(e.clone()),
            pending: None,
        },
        writes: 0,
        applies: 0,
    };
    // nft 1.1.6 omits redundant l4proto when a typed TCP/UDP payload
    // already establishes it. This is the observed native roundtrip shape.
    for item in guard.nft["nftables"].as_array_mut().unwrap() {
        if let Some(xs) = item
            .get_mut("rule")
            .and_then(|r| r.get_mut("expr"))
            .and_then(Value::as_array_mut)
        {
            xs.retain(|e| e["match"]["left"] != json!({"meta":{"key":"l4proto"}}));
        }
    }
    for _ in 0..3 {
        explicit::reconcile(&mut guard, Some(&e)).unwrap();
    }
    assert_eq!((guard.writes, guard.applies), (0, 0));
    guard.nft["nftables"][0]["table"]["comment"] = json!("foreign-owner");
    assert!(explicit::reconcile(&mut guard, None).is_err());
    assert_eq!((guard.writes, guard.applies), (0, 0));
}
