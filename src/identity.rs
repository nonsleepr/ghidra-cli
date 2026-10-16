//! Diagnostic identities, not cryptographic authenticity guarantees.
use serde_json::{json, Value};

pub const BRIDGE_PROTOCOL_VERSION: u32 = 1;

pub fn client_identity() -> Value {
    json!({
        "name": "ghidra-cli",
        "version": env!("CARGO_PKG_VERSION"),
        "build_id": env!("GHIDRA_CLI_BUILD_ID"),
        "source_revision": env!("GHIDRA_CLI_REVISION"),
        "target": env!("GHIDRA_CLI_TARGET"),
        "executable": std::env::current_exe().ok(),
        "bridge_script_hash": crate::ghidra::bridge::script_hash(),
        "bridge_protocol_version": BRIDGE_PROTOCOL_VERSION,
    })
}

pub fn compatibility(info: &Value) -> Value {
    let protocol = match info["protocol_version"].as_u64() {
        Some(v) if v == u64::from(BRIDGE_PROTOCOL_VERSION) => "match",
        Some(_) => "mismatch",
        None => "unknown",
    };
    let script = match info["script_hash"].as_str() {
        Some(v) if v == crate::ghidra::bridge::script_hash() => "match",
        Some(_) => "mismatch",
        None => "unknown",
    };
    json!({"protocol": protocol, "script": script,
        "policy": "Protocol mismatches are rejected; script differences alone do not restart a bridge. Unknown commands trigger one refresh and retry."})
}

pub fn check_protocol(info: &Value) -> anyhow::Result<()> {
    if compatibility(info)["protocol"] == "mismatch" {
        anyhow::bail!("Bridge protocol {} differs from CLI protocol {}. Inspect 'status --json' and explicitly restart this project's bridge.", info["protocol_version"], BRIDGE_PROTOCOL_VERSION);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn legacy_and_incompatible_bridges_are_distinct() {
        assert_eq!(compatibility(&json!({}))["protocol"], "unknown");
        assert!(check_protocol(&json!({})).is_ok());
        let info = json!({"protocol_version": BRIDGE_PROTOCOL_VERSION, "script_hash": crate::ghidra::bridge::script_hash()});
        assert_eq!(compatibility(&info)["script"], "match");
        assert!(check_protocol(&info).is_ok());
        assert!(check_protocol(&json!({"protocol_version": 999})).is_err());
    }
}
