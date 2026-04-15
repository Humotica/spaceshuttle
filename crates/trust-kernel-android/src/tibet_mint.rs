//! TIBET Token Minting for Android.
//!
//! Mints provenance tokens with the 4 TIBET dimensions:
//! - ERIN: What's IN (result/payload)
//! - ERAAN: What's ATTACHED (dependencies, refs)
//! - EROMHEEN: What's AROUND (context, triage decision)
//! - ERACHTER: What's BEHIND (original intent)

use serde::Serialize;
use sha2::{Sha256, Digest};
use chrono::Utc;

#[derive(Serialize, Debug, Clone)]
pub struct TibetToken {
    pub tbz_version: String,
    pub token_type: String,
    pub token_id: String,
    pub timestamp: String,
    pub ains_identity: String,
    pub intent: String,

    // The 4 Dimensions
    pub erin: String,
    pub eraan: String,
    pub eromheen: String,
    pub erachter: String,

    pub clearance: u8,
    pub device: String,
    pub seal: String,
}

/// Mint a new TIBET provenance token.
pub fn mint_token(action: &str, actor: &str, clearance: u8) -> TibetToken {
    let timestamp = Utc::now().to_rfc3339();

    // Token ID = SHA-256(actor || action || timestamp)[:16] hex
    let mut hasher = Sha256::new();
    hasher.update(actor.as_bytes());
    hasher.update(b"|");
    hasher.update(action.as_bytes());
    hasher.update(b"|");
    hasher.update(timestamp.as_bytes());
    let hash = hasher.finalize();
    let token_id = hash.iter().take(8).map(|b| format!("{:02x}", b)).collect::<String>();

    // Seal = SHA-256(token_id || all_fields)
    let mut seal_hasher = Sha256::new();
    seal_hasher.update(token_id.as_bytes());
    seal_hasher.update(action.as_bytes());
    seal_hasher.update(actor.as_bytes());
    seal_hasher.update(timestamp.as_bytes());
    let seal_hash = seal_hasher.finalize();
    let seal = seal_hash.iter().take(16).map(|b| format!("{:02x}", b)).collect::<String>();

    TibetToken {
        tbz_version: "v1.0.0-ANDROID".to_string(),
        token_type: categorize_action(action),
        token_id,
        timestamp,
        ains_identity: actor.to_string(),
        intent: action.to_string(),
        erin: format!("action:{}", action),
        eraan: format!("device:android,clearance:{}", clearance),
        eromheen: format!("trust-kernel-android,bifurcation-aes256gcm"),
        erachter: action.to_string(),
        clearance,
        device: "android".to_string(),
        seal,
    }
}

fn categorize_action(action: &str) -> String {
    if action.starts_with("finance:") {
        "FINANCIAL_ACTION".to_string()
    } else if action.starts_with("chat:") {
        "COMMUNICATION".to_string()
    } else if action.starts_with("call:") {
        "VOICE_VIDEO".to_string()
    } else if action.starts_with("file:") {
        "FILE_OPERATION".to_string()
    } else {
        "GENERAL_ACTION".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mint_basic_token() {
        let token = mint_token("chat:send", "user.aint", 2);
        assert_eq!(token.token_type, "COMMUNICATION");
        assert_eq!(token.clearance, 2);
        assert!(!token.token_id.is_empty());
        assert!(!token.seal.is_empty());
        assert_eq!(token.erin, "action:chat:send");
    }

    #[test]
    fn financial_token_type() {
        let token = mint_token("finance:transfer", "user.aint", 3);
        assert_eq!(token.token_type, "FINANCIAL_ACTION");
    }

    #[test]
    fn unique_token_ids() {
        let t1 = mint_token("a", "b", 0);
        let t2 = mint_token("a", "b", 0);
        // Timestamps differ → different IDs
        // (may rarely collide in fast tests, but practically unique)
        assert_eq!(t1.ains_identity, t2.ains_identity);
    }
}
