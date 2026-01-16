//! CryptoBox: End-to-End Encryption Utilities
//!
//! This module provides functions for encrypting and decrypting data using
//! public-key authenticated encryption (Curve25519 + XSalsa20 + Poly1305) via sodiumoxide.
//!
//! It supports:
//! - Encrypting with a sender secret key and recipient public key (`encrypt_box`)
//! - Encrypting with an ephemeral recipient key (`encrypt_ephemeral_box`)
//! - Decrypting messages using recipient secret key and sender public key (`decrypt_box`)
//! - Generating secure nonces (`gen_nonce_b64`)
//!
//! # Example: Regular Box
//! ```rust
//! use crypto_box::{encrypt_box, decrypt_box};
//!
//! let plaintext = "Hello World";
//!
//! let (sender_pk, sender_sk) = sodiumoxide::crypto::box_::gen_keypair();
//! let (recipient_pk, recipient_sk) = sodiumoxide::crypto::box_::gen_keypair();
//!
//! let encrypted = encrypt_box(
//!     plaintext,
//!     &base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(recipient_pk.as_ref()),
//!     &hex::encode(sender_sk.as_ref())
//! ).unwrap();
//!
//! let decrypted = decrypt_box(
//!     &encrypted.ciphertext,
//!     &encrypted.nonce,
//!     &base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sender_pk.as_ref()),
//!     &hex::encode(recipient_sk.as_ref())
//! ).unwrap();
//!
//! assert_eq!(decrypted, plaintext);
//! ```
//!
//! # Example: Ephemeral Box
//! ```rust
//! use crypto_box::{encrypt_ephemeral_box};
//!
//! let (sender_pk, sender_sk) = sodiumoxide::crypto::box_::gen_keypair();
//! let plaintext = "Hello Ephemeral";
//!
//! let encrypted = encrypt_ephemeral_box(plaintext, &hex::encode(sender_sk.as_ref())).unwrap();
//!
//! println!("Ciphertext: {}", encrypted.ciphertext);
//! println!("Nonce: {}", encrypted.nonce);
//! println!("Ephemeral Public Key: {}", encrypted.ephemeral_public_key);
//! ```

use anyhow::{Result, anyhow};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hex::decode as hex_decode;
use serde::{Deserialize, Serialize};
use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::box_::{Nonce, PublicKey, SecretKey};
use utoipa::ToSchema;

/// Decodes a Base64 string into bytes
fn decode_b64(input: &str) -> Result<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(input)
        .map_err(|_| anyhow!("Invalid Base64 input"))
}

/// Encodes bytes into a Base64 string
fn encode_b64(input: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(input)
}

/// Encrypts a plaintext message using the sender's secret key and recipient's public key
///
/// # Arguments
/// * `plaintext` - UTF-8 string to encrypt
/// * `recipient_pub_b64` - Base64-encoded recipient public key
/// * `sender_secret_hex` - Hex-encoded sender secret key
///
/// # Returns
/// Base64-encoded ciphertext and nonce
pub fn encrypt_box(
    plaintext: &str,
    recipient_pub_b64: &str,
    sender_secret_hex: &str,
) -> Result<EncryptedMessage> {
    sodiumoxide::init().map_err(|_| anyhow!("Failed to initialize sodiumoxide"))?;

    let sender_sk_bytes = hex_decode(sender_secret_hex)?;
    let sender_sk = SecretKey::from_slice(&sender_sk_bytes)
        .ok_or_else(|| anyhow!("Invalid sender secret key"))?;

    let recipient_pk_bytes = decode_b64(recipient_pub_b64)?;
    let recipient_pk = PublicKey::from_slice(&recipient_pk_bytes)
        .ok_or_else(|| anyhow!("Invalid recipient public key"))?;

    // Generate random nonce
    let nonce = box_::gen_nonce();
    let nonce_b64 = encode_b64(nonce.as_ref());
    let ciphertext = box_::seal(plaintext.as_bytes(), &nonce, &recipient_pk, &sender_sk);

    Ok(EncryptedMessage {
        ciphertext: encode_b64(&ciphertext),
        nonce: nonce_b64,
    })
}

/// Encrypts a plaintext message using the sender's secret key
///
/// # Arguments
/// * `plaintext` - UTF-8 string to encrypt
/// * `sender_public_key` - Base-64 sender public key
///
/// # Returns
/// Base64-encoded ciphertext, nonce, and ephemeral public key
pub fn encrypt_ephemeral_box(
    plaintext: &str,
    sender_pub_b64: &str,
) -> Result<EncryptedEphemeralMessage> {
    sodiumoxide::init().map_err(|_| anyhow!("Failed to initialize sodiumoxide"))?;

    let sender_pk_bytes = decode_b64(sender_pub_b64)?;
    let sender_pk = PublicKey::from_slice(&sender_pk_bytes)
        .ok_or_else(|| anyhow!("Invalid sender public key"))?;

    let (_ephemeral_pk, ephemeral_sk) = box_::gen_keypair();
    let recipient_sk = SecretKey::from_slice(&ephemeral_sk.as_ref())
        .ok_or_else(|| anyhow!("Invalid recipient secret key"))?;

    // Generate random nonce
    let nonce = box_::gen_nonce();
    let nonce_b64 = encode_b64(nonce.as_ref());
    let ciphertext = box_::seal(plaintext.as_bytes(), &nonce, &sender_pk, &recipient_sk);

    Ok(EncryptedEphemeralMessage {
        ciphertext: encode_b64(&ciphertext),
        nonce: nonce_b64,
        ephemeral_secret_key: encode_b64(ephemeral_sk.as_ref()),
    })
}

/// Decrypts a ciphertext message using the recipient's secret key and sender's public key
///
/// # Arguments
/// * `ciphertext_b64` - Base64-encoded ciphertext
/// * `nonce_b64` - Base64-encoded nonce
/// * `sender_pub_b64` - Base64-encoded sender public key
/// * `recipient_secret_hex` - Hex-encoded recipient secret key
///
/// # Returns
/// UTF-8 decrypted plaintext
pub fn decrypt_box(
    ciphertext_b64: &str,
    nonce_b64: &str,
    sender_pub_b64: &str,
    recipient_secret_hex: &str,
) -> Result<String> {
    sodiumoxide::init().map_err(|_| anyhow!("Failed to initialize sodiumoxide"))?;

    let recipient_sk_bytes = hex_decode(recipient_secret_hex)?;
    let recipient_sk = SecretKey::from_slice(&recipient_sk_bytes)
        .ok_or_else(|| anyhow!("Invalid recipient secret key"))?;

    let sender_pk_bytes = decode_b64(sender_pub_b64)?;
    let sender_pk = PublicKey::from_slice(&sender_pk_bytes)
        .ok_or_else(|| anyhow!("Invalid sender public key"))?;

    let nonce_bytes = decode_b64(nonce_b64)?;
    let nonce = Nonce::from_slice(&nonce_bytes).ok_or_else(|| anyhow!("Invalid nonce"))?;

    let ciphertext = decode_b64(ciphertext_b64)?;
    let decrypted = box_::open(&ciphertext, &nonce, &sender_pk, &recipient_sk)
        .map_err(|_| anyhow!("Decryption failed"))?;

    String::from_utf8(decrypted).map_err(|_| anyhow!("Decrypted data is not valid UTF-8"))
}

/// Generates a new random nonce and returns it Base64-encoded
pub fn gen_nonce_b64() -> String {
    let nonce = box_::gen_nonce();
    encode_b64(nonce.as_ref())
}

/// Represents an encrypted payload with nonce
#[derive(Debug, Serialize, Deserialize, Clone, ToSchema)]
pub struct EncryptedMessage {
    /// Base64-encoded ciphertext
    pub ciphertext: String,
    /// Base64-encoded nonce
    pub nonce: String,
}

/// Represents an encrypted payload with nonce and ephemeral public key
#[derive(Debug, Serialize, Deserialize, Clone, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedEphemeralMessage {
    /// Base64-encoded ciphertext
    pub ciphertext: String,
    /// Base64-encoded nonce
    pub nonce: String,
    /// Base64-encoded sender secret key
    pub ephemeral_secret_key: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use sodiumoxide::crypto::box_;

    #[test]
    fn test_encrypt_ephemeral_box() {
        sodiumoxide::init().unwrap();
        let (sender_pk, _sender_sk) = box_::gen_keypair();
        let plaintext = "ephemeral message";

        let encrypted = encrypt_ephemeral_box(plaintext, &encode_b64(sender_pk.as_ref())).unwrap();
        
        assert!(!encrypted.ciphertext.is_empty());
        assert!(!encrypted.nonce.is_empty());
        assert!(!encrypted.ephemeral_secret_key.is_empty());
    }

    #[test]
    fn test_encrypt_decrypt_success() {
        sodiumoxide::init().unwrap();

        let (client_pk, client_sk) = box_::gen_keypair();
        let (server_pk, server_sk) = box_::gen_keypair();
        let plaintext = "secure message";

        let EncryptedMessage { ciphertext, nonce } = encrypt_box(
            plaintext,
            &encode_b64(server_pk.as_ref()),
            &hex::encode(client_sk.as_ref()),
        )
        .unwrap();

        let decrypted = decrypt_box(
            &ciphertext,
            &nonce,
            &encode_b64(client_pk.as_ref()),
            &hex::encode(server_sk.as_ref()),
        )
        .unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_decrypt_failure_invalid_keys() {
        sodiumoxide::init().unwrap();

        let (client_pk, client_sk) = box_::gen_keypair();
        let (server_pk, _) = box_::gen_keypair();

        let EncryptedMessage { ciphertext, nonce } = encrypt_box(
            "message",
            &encode_b64(server_pk.as_ref()),
            &hex::encode(client_sk.as_ref()),
        )
        .unwrap();

        // Attempt decrypt with wrong server key
        let wrong_sk = box_::gen_keypair().1;
        let result = decrypt_box(
            &ciphertext,
            &nonce,
            &encode_b64(client_pk.as_ref()),
            &hex::encode(wrong_sk.as_ref()),
        );

        assert!(result.is_err());
    }
}
