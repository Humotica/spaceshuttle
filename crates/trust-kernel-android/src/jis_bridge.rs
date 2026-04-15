//! JIS Bridge — Accept Android DID public key as identity for JIS claims.
//!
//! Android Keystore uses ECDSA P-256, Trust Kernel uses Ed25519.
//! Phase 1: DID pubkey hex is used as an opaque identity token.
//! Phase 2: BouncyCastle Ed25519 or API 33+ Keystore integration.

use serde::Serialize;
use sha2::{Sha256, Digest};
use chrono::Utc;

/// JIS Claim for Android — maps to the Trust Kernel JisClaim struct.
#[derive(Serialize, Debug, Clone)]
pub struct AndroidJisClaim {
    pub identity: String,
    pub did_pub_hex: String,
    pub clearance: u8,
    pub clearance_label: String,
    pub role: String,
    pub claimed_at: String,
    pub fingerprint: String,
}

/// Create a JIS claim from an Android DID public key.
///
/// The DID public key (ECDSA P-256, base64-encoded from Android Keystore)
/// is used as the identity binding. The fingerprint is SHA-256(pubkey).
pub fn create_claim(did_pub_hex: &str, identity: &str, clearance: u8) -> AndroidJisClaim {
    let clearance_label = match clearance {
        0 => "UNCLASSIFIED",
        1 => "RESTRICTED",
        2 => "CONFIDENTIAL",
        3 => "SECRET",
        _ => "TOPSECRET",
    };

    // SHA-256 fingerprint of the DID public key
    let mut hasher = Sha256::new();
    hasher.update(did_pub_hex.as_bytes());
    let hash = hasher.finalize();
    let fingerprint = hex::encode(&hash[..8]); // First 8 bytes as short fingerprint

    AndroidJisClaim {
        identity: identity.to_string(),
        did_pub_hex: did_pub_hex.to_string(),
        clearance,
        clearance_label: clearance_label.to_string(),
        role: "device_owner".to_string(),
        claimed_at: Utc::now().to_rfc3339(),
        fingerprint,
    }
}

// Inline hex encoding (avoid extra dependency)
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_claim_basic() {
        let claim = create_claim(
            "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...",
            "user@device.aint",
            2,
        );
        assert_eq!(claim.clearance, 2);
        assert_eq!(claim.clearance_label, "CONFIDENTIAL");
        assert!(!claim.fingerprint.is_empty());
    }

    #[test]
    fn clearance_labels() {
        assert_eq!(create_claim("k", "id", 0).clearance_label, "UNCLASSIFIED");
        assert_eq!(create_claim("k", "id", 1).clearance_label, "RESTRICTED");
        assert_eq!(create_claim("k", "id", 3).clearance_label, "SECRET");
        assert_eq!(create_claim("k", "id", 4).clearance_label, "TOPSECRET");
    }
}
