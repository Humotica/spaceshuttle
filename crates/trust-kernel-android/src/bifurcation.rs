//! Bifurcation Engine for Android — AES-256-GCM seal/open
//!
//! Simplified version of the full Trust Kernel bifurcation:
//! - No userfaultfd (not available on Android)
//! - No rayon parallel batch (single-threaded JNI calls)
//! - Session-based: one DH per session, HKDF per block

use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, KeyInit};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use rand::rngs::OsRng;

const NONCE_SIZE: usize = 12;
const KEY_SIZE: usize = 32;

/// Lightweight Bifurcation engine for Android JNI.
///
/// Wire format for sealed data:
///   [32 bytes ephemeral_pub] [12 bytes nonce] [N bytes ciphertext+tag]
pub struct AndroidBifurcation {
    /// Session secret (32 bytes)
    secret: [u8; KEY_SIZE],
    /// Derived public key
    public: [u8; KEY_SIZE],
    /// Block counter for unique HKDF derivation
    block_counter: u64,
}

impl AndroidBifurcation {
    /// Create a session from a 32-byte key.
    pub fn new(key: [u8; KEY_SIZE]) -> Self {
        let static_secret = StaticSecret::from(key);
        let public = PublicKey::from(&static_secret);
        Self {
            secret: key,
            public: public.to_bytes(),
            block_counter: 0,
        }
    }

    /// Create a session with a random key (for testing).
    pub fn random() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self {
            secret: secret.to_bytes(),
            public: public.to_bytes(),
            block_counter: 0,
        }
    }

    /// Seal: encrypt plaintext → wire format bytes.
    ///
    /// Output: [ephemeral_pub:32][nonce:12][ciphertext+tag:N+16]
    pub fn seal(&mut self, plaintext: &[u8]) -> Vec<u8> {
        self.block_counter += 1;

        // Ephemeral keypair for this block
        let ephemeral_secret = StaticSecret::random_from_rng(OsRng);
        let ephemeral_pub = PublicKey::from(&ephemeral_secret);

        // X25519 DH: shared = ephemeral_secret * session_pub
        let session_pub = PublicKey::from(self.public);
        let shared = ephemeral_secret.diffie_hellman(&session_pub);

        // HKDF: shared → per-block AES key
        let aes_key = self.hkdf_derive(shared.as_bytes(), self.block_counter);

        // Generate nonce from block counter + random
        let nonce = self.generate_nonce(self.block_counter);

        // AES-256-GCM encrypt
        let key = Key::<Aes256Gcm>::from_slice(&aes_key);
        let cipher = Aes256Gcm::new(key);
        let nonce_ref = Nonce::from_slice(&nonce);
        let ciphertext = cipher.encrypt(nonce_ref, plaintext).expect("encryption failed");

        // Pack: [ephemeral_pub:32][nonce:12][ciphertext+tag]
        let mut output = Vec::with_capacity(KEY_SIZE + NONCE_SIZE + ciphertext.len());
        output.extend_from_slice(&ephemeral_pub.to_bytes());
        output.extend_from_slice(&nonce);
        output.extend_from_slice(&ciphertext);
        output
    }

    /// Open: decrypt wire format bytes → plaintext.
    ///
    /// Input: [ephemeral_pub:32][nonce:12][ciphertext+tag:N+16]
    pub fn open(&self, sealed: &[u8]) -> Option<Vec<u8>> {
        if sealed.len() < KEY_SIZE + NONCE_SIZE + 16 {
            return None; // Too short (need pub + nonce + at least tag)
        }

        // Unpack
        let ephemeral_pub_bytes: [u8; 32] = sealed[..KEY_SIZE].try_into().ok()?;
        let nonce: [u8; 12] = sealed[KEY_SIZE..KEY_SIZE + NONCE_SIZE].try_into().ok()?;
        let ciphertext = &sealed[KEY_SIZE + NONCE_SIZE..];

        // X25519 DH: shared = session_secret * ephemeral_pub
        let system_static = StaticSecret::from(self.secret);
        let ephemeral_pub = PublicKey::from(ephemeral_pub_bytes);
        let shared = system_static.diffie_hellman(&ephemeral_pub);

        // We need the block counter that was used during seal.
        // Try with a brute-force over recent blocks (max 1000 ahead).
        // In practice, the caller should track block indices.
        // Optimization: try common counters first.
        for block_idx in 0..=self.block_counter + 1000 {
            let aes_key = self.hkdf_derive(shared.as_bytes(), block_idx);
            let key = Key::<Aes256Gcm>::from_slice(&aes_key);
            let cipher = Aes256Gcm::new(key);
            let nonce_ref = Nonce::from_slice(&nonce);

            if let Ok(plaintext) = cipher.decrypt(nonce_ref, ciphertext) {
                return Some(plaintext);
            }
        }

        None
    }

    /// HKDF-SHA256: shared secret + block index → AES-256 key
    fn hkdf_derive(&self, shared: &[u8], block_index: u64) -> [u8; KEY_SIZE] {
        let salt = format!("TIBET-BIFURCATION-ANDROID-{}", block_index);
        let hk = Hkdf::<Sha256>::new(Some(salt.as_bytes()), shared);
        let mut key = [0u8; KEY_SIZE];
        hk.expand(b"aes-256-gcm-key", &mut key).expect("hkdf expand");
        key
    }

    /// Generate a nonce from block counter.
    fn generate_nonce(&self, block_index: u64) -> [u8; NONCE_SIZE] {
        let mut nonce = [0u8; NONCE_SIZE];
        nonce[..8].copy_from_slice(&block_index.to_le_bytes());
        // Last 4 bytes: random for uniqueness
        let random_bytes: [u8; 4] = rand::random();
        nonce[8..].copy_from_slice(&random_bytes);
        nonce
    }
}

impl Drop for AndroidBifurcation {
    fn drop(&mut self) {
        // Zero out sensitive key material
        self.secret = [0u8; KEY_SIZE];
        self.public = [0u8; KEY_SIZE];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip() {
        let key = [42u8; 32];
        let mut session = AndroidBifurcation::new(key);
        let plaintext = b"Hello from Android Trust Kernel!";

        let sealed = session.seal(plaintext);
        assert!(sealed.len() > KEY_SIZE + NONCE_SIZE + 16);

        let opened = session.open(&sealed);
        assert!(opened.is_some());
        assert_eq!(opened.unwrap(), plaintext);
    }

    #[test]
    fn random_session_works() {
        let mut session = AndroidBifurcation::random();
        let data = b"TIBET provenance test data";

        let sealed = session.seal(data);
        let opened = session.open(&sealed);
        assert_eq!(opened.unwrap(), data);
    }

    #[test]
    fn wrong_key_fails() {
        let mut session_a = AndroidBifurcation::new([1u8; 32]);
        let session_b = AndroidBifurcation::new([2u8; 32]);

        let sealed = session_a.seal(b"secret data");
        let opened = session_b.open(&sealed);
        assert!(opened.is_none());
    }

    #[test]
    fn too_short_returns_none() {
        let session = AndroidBifurcation::new([1u8; 32]);
        assert!(session.open(&[0u8; 10]).is_none());
    }
}
