/// ACP-1 Cryptographic Layer (Rust implementation)
/// Must produce identical output to Node.js crypto.ts — LOCKED protocol.

use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, KeyInit};
use hkdf::Hkdf;
use sha2::Sha256;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use rand::RngCore;
use serde::{Deserialize, Serialize};

const EXTRACT_SALT: &[u8] = b"acp1:extract";
const IV_LENGTH: usize = 12;
const KEY_LENGTH: usize = 32;
const TOPIC_LENGTH: usize = 16;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EncryptedPayload {
    pub iv: String,
    pub data: String,
    pub tag: String,
}

/// Single HKDF call: Extract + Expand
fn hkdf_derive(ikm: &[u8], info: &str, length: usize) -> Vec<u8> {
    let hk = Hkdf::<Sha256>::new(Some(EXTRACT_SALT), ikm);
    let mut okm = vec![0u8; length];
    hk.expand(info.as_bytes(), &mut okm)
        .expect("HKDF expand failed");
    okm
}

/// Derive channel encryption key (epoch 0)
pub fn derive_key(channel_key: &str) -> Vec<u8> {
    hkdf_derive(channel_key.as_bytes(), "acp1:enc:channel:epoch:0", KEY_LENGTH)
}

/// Derive subchannel encryption key (epoch 0)
pub fn derive_sub_key(channel_key: &str, sub_name: &str) -> Vec<u8> {
    let info = format!("acp1:enc:sub:{}:epoch:0", sub_name);
    hkdf_derive(channel_key.as_bytes(), &info, KEY_LENGTH)
}

/// Derive channel topic ID (128-bit, 32 hex chars)
pub fn hash_room(channel_key: &str) -> String {
    let bytes = hkdf_derive(channel_key.as_bytes(), "acp1:topic:channel", TOPIC_LENGTH);
    hex::encode(bytes)
}

/// Derive subchannel topic ID (128-bit, 32 hex chars)
pub fn hash_sub(channel_key: &str, sub_name: &str) -> String {
    let info = format!("acp1:topic:sub:{}", sub_name);
    let bytes = hkdf_derive(channel_key.as_bytes(), &info, TOPIC_LENGTH);
    hex::encode(bytes)
}

/// AES-256-GCM encrypt
pub fn encrypt(plaintext: &str, key: &[u8]) -> EncryptedPayload {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let mut iv_bytes = [0u8; IV_LENGTH];
    rand::thread_rng().fill_bytes(&mut iv_bytes);
    let nonce = Nonce::from_slice(&iv_bytes);

    let ciphertext = cipher.encrypt(nonce, plaintext.as_bytes())
        .expect("encryption failed");

    // AES-GCM appends 16-byte tag to ciphertext
    let (data, tag) = ciphertext.split_at(ciphertext.len() - 16);

    EncryptedPayload {
        iv: BASE64.encode(iv_bytes),
        data: BASE64.encode(data),
        tag: BASE64.encode(tag),
    }
}

/// AES-256-GCM decrypt
pub fn decrypt(payload: &EncryptedPayload, key: &[u8]) -> Result<String, String> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let iv = BASE64.decode(&payload.iv).map_err(|e| e.to_string())?;
    let data = BASE64.decode(&payload.data).map_err(|e| e.to_string())?;
    let tag = BASE64.decode(&payload.tag).map_err(|e| e.to_string())?;

    let nonce = Nonce::from_slice(&iv);
    let mut combined = data;
    combined.extend_from_slice(&tag);

    let plaintext = cipher.decrypt(nonce, combined.as_ref())
        .map_err(|_| "decryption failed".to_string())?;

    String::from_utf8(plaintext).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_derivation_matches_nodejs() {
        // These values must match Node.js output for the same input
        let key = "G1jNByNEoQGxiztw";
        let enc_key = derive_key(key);
        let topic = hash_room(key);

        // Node.js: e4bd3ef85388ef06e2e6375395fca836553e3d02ea24cb15ca341a1a2877bd1c
        assert_eq!(hex::encode(&enc_key), "e4bd3ef85388ef06e2e6375395fca836553e3d02ea24cb15ca341a1a2877bd1c");
        // Node.js: e0546ca404e1766ea5bc01026946e2f6
        assert_eq!(topic, "e0546ca404e1766ea5bc01026946e2f6");
    }

    #[test]
    fn test_encrypt_decrypt() {
        let key = derive_key("test-key");
        let plaintext = "Hello, AgentChannel!";
        let encrypted = encrypt(plaintext, &key);
        let decrypted = decrypt(&encrypted, &key).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_subchannel_derivation() {
        let key = "G1jNByNEoQGxiztw";
        let sub_key = derive_sub_key(key, "product");
        let sub_topic = hash_sub(key, "product");

        // Must be different from channel key/topic
        assert_ne!(hex::encode(&sub_key), hex::encode(derive_key(key)));
        assert_ne!(sub_topic, hash_room(key));
    }
}
