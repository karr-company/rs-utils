//! E2E Crypto: Node.js-Compatible End-to-End Encryption
//!
//! This module provides true end-to-end encryption using standard algorithms
//! compatible with Node.js crypto and Web Crypto API:
//!
//! - **Key Exchange**: X25519 ECDH (Curve25519 Diffie-Hellman)
//! - **Key Derivation**: HKDF-SHA256
//! - **Encryption**: AES-256-GCM (authenticated encryption)
//!
//! ## Security Model
//!
//! 1. Client generates an ephemeral X25519 keypair per session/request
//! 2. Client sends its ephemeral PUBLIC key with the request (header or body)
//! 3. Server generates its own ephemeral keypair per response
//! 4. Server computes shared secret: ECDH(server_sk, client_pk)
//! 5. Server derives AES key via HKDF(shared_secret, salt, info)
//! 6. Server encrypts response with AES-256-GCM
//! 7. Server sends: { ciphertext, iv, authTag, serverPublicKey }
//! 8. Client computes same shared secret: ECDH(client_sk, server_pk)
//! 9. Client derives same AES key and decrypts
//!
//! ## Why This Is Secure
//!
//! - No secret key material is transmitted (only public keys)
//! - Each response uses a fresh ephemeral keypair (forward secrecy)
//! - AES-GCM provides both confidentiality and integrity
//! - HKDF ensures proper key derivation from ECDH output
//! - Compatible with MITM protection via JWT authentication layer
//!
//! ## Node.js Compatibility
//!
//! ```javascript
//! const crypto = require('crypto');
//!
//! // Generate X25519 keypair
//! const { publicKey, privateKey } = crypto.generateKeyPairSync('x25519');
//!
//! // Compute shared secret
//! const sharedSecret = crypto.diffieHellman({
//!   privateKey: clientPrivateKey,
//!   publicKey: serverPublicKey
//! });
//!
//! // Derive AES key via HKDF
//! const aesKey = crypto.hkdfSync('sha256', sharedSecret, salt, info, 32);
//!
//! // Decrypt with AES-256-GCM
//! const decipher = crypto.createDecipheriv('aes-256-gcm', aesKey, iv);
//! decipher.setAuthTag(authTag);
//! const plaintext = decipher.update(ciphertext) + decipher.final();
//! ```
//!
//! ## Example Usage (Rust Server)
//!
//! ```rust
//! use rs_utils::e2e_crypto::{E2eEncryptedMessage, encrypt_for_client, generate_keypair};
//!
//! // Client's public key from request header
//! let client_pub_b64 = "base64_encoded_client_public_key";
//!
//! // Encrypt response
//! let plaintext = r#"{"customerId": "cus_xxx", "secret": "sensitive_data"}"#;
//! let encrypted = encrypt_for_client(plaintext, client_pub_b64)?;
//!
//! // Send encrypted response (JSON serializable)
//! let response_body = serde_json::to_string(&encrypted)?;
//! ```

use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, AeadCore, OsRng as AeadOsRng},
};
use anyhow::{Result, anyhow};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hkdf::Hkdf;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use utoipa::ToSchema;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

/// HKDF info string for context binding
const HKDF_INFO: &[u8] = b"karr-e2e-aes-key-v1";

/// HKDF salt (can be empty for HKDF, but we use a fixed value for domain separation)
const HKDF_SALT: &[u8] = b"karr-e2e-salt-v1";

// Types

/// X25519 keypair for ECDH key exchange
#[derive(Clone)]
pub struct E2eKeyPair {
    /// Base64-encoded public key (32 bytes)
    pub public_key: String,
    /// Raw secret key bytes (for internal use)
    secret_key: [u8; 32],
}

impl E2eKeyPair {
    /// Get the secret key for ECDH computation
    pub fn secret_key_bytes(&self) -> &[u8; 32] {
        &self.secret_key
    }
}

/// Encrypted message format for E2E responses
///
/// This structure is JSON-serializable and contains all information
/// needed for the client to decrypt the message.
#[derive(Debug, Serialize, Deserialize, Clone, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct E2eEncryptedMessage {
    /// Base64-encoded AES-GCM ciphertext
    pub ciphertext: String,

    /// Base64-encoded 12-byte IV/nonce
    pub iv: String,

    /// Base64-encoded 16-byte authentication tag
    pub auth_tag: String,

    /// Base64-encoded server's ephemeral X25519 public key (32 bytes)
    pub server_public_key: String,
}

/// Request format when client sends encrypted data
#[derive(Debug, Serialize, Deserialize, Clone, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct E2eEncryptedRequest {
    /// Base64-encoded AES-GCM ciphertext
    pub ciphertext: String,

    /// Base64-encoded 12-byte IV/nonce
    pub iv: String,

    /// Base64-encoded 16-byte authentication tag
    pub auth_tag: String,

    /// Base64-encoded client's ephemeral X25519 public key (32 bytes)
    pub client_public_key: String,
}

// Key Generation

/// Generates a new X25519 keypair for ECDH key exchange
///
/// # Returns
/// An `E2eKeyPair` containing the public key (base64) and secret key bytes
///
/// # Example
/// ```rust
/// let keypair = generate_keypair();
/// println!("Public key: {}", keypair.public_key);
/// ```
pub fn generate_keypair() -> E2eKeyPair {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);

    E2eKeyPair {
        public_key: URL_SAFE_NO_PAD.encode(public.as_bytes()),
        secret_key: secret.to_bytes(),
    }
}

/// Generates an ephemeral keypair (one-time use)
///
/// Uses `EphemeralSecret` which is consumed on use, providing forward secrecy.
fn generate_ephemeral_keypair() -> (EphemeralSecret, PublicKey) {
    let secret = EphemeralSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    (secret, public)
}

// ECDH + HKDF Key Derivation

/// Computes shared secret and derives AES-256 key
///
/// # Arguments
/// * `our_secret` - Our X25519 secret key bytes
/// * `their_public_b64` - Their base64-encoded public key
///
/// # Returns
/// 32-byte AES-256 key derived via HKDF-SHA256
fn derive_shared_key(our_secret: &[u8; 32], their_public_b64: &str) -> Result<[u8; 32]> {
    // Decode their public key
    let their_public_bytes = URL_SAFE_NO_PAD
        .decode(their_public_b64)
        .map_err(|_| anyhow!("Invalid base64 public key"))?;

    if their_public_bytes.len() != 32 {
        return Err(anyhow!(
            "Invalid public key length: expected 32, got {}",
            their_public_bytes.len()
        ));
    }

    let their_public: [u8; 32] = their_public_bytes
        .try_into()
        .map_err(|_| anyhow!("Failed to convert public key bytes"))?;

    // Compute ECDH shared secret
    let our_static = StaticSecret::from(*our_secret);
    let their_pk = PublicKey::from(their_public);
    let shared_secret = our_static.diffie_hellman(&their_pk);

    // Derive AES key via HKDF-SHA256
    let hkdf = Hkdf::<Sha256>::new(Some(HKDF_SALT), shared_secret.as_bytes());
    let mut aes_key = [0u8; 32];
    hkdf.expand(HKDF_INFO, &mut aes_key)
        .map_err(|_| anyhow!("HKDF expansion failed"))?;

    Ok(aes_key)
}

/// Computes shared secret from ephemeral secret (consuming it)
fn derive_shared_key_ephemeral(
    our_secret: EphemeralSecret,
    their_public_b64: &str,
) -> Result<[u8; 32]> {
    // Decode their public key
    let their_public_bytes = URL_SAFE_NO_PAD
        .decode(their_public_b64)
        .map_err(|_| anyhow!("Invalid base64 public key"))?;

    if their_public_bytes.len() != 32 {
        return Err(anyhow!(
            "Invalid public key length: expected 32, got {}",
            their_public_bytes.len()
        ));
    }

    let their_public: [u8; 32] = their_public_bytes
        .try_into()
        .map_err(|_| anyhow!("Failed to convert public key bytes"))?;

    // Compute ECDH shared secret (consumes ephemeral secret)
    let their_pk = PublicKey::from(their_public);
    let shared_secret = our_secret.diffie_hellman(&their_pk);

    // Derive AES key via HKDF-SHA256
    let hkdf = Hkdf::<Sha256>::new(Some(HKDF_SALT), shared_secret.as_bytes());
    let mut aes_key = [0u8; 32];
    hkdf.expand(HKDF_INFO, &mut aes_key)
        .map_err(|_| anyhow!("HKDF expansion failed"))?;

    Ok(aes_key)
}

// Encryption (Server → Client)

/// Encrypts a message for a specific client using their public key
///
/// This is the primary function for server-side response encryption.
/// It generates a fresh ephemeral keypair for each encryption, providing
/// forward secrecy.
///
/// # Arguments
/// * `plaintext` - UTF-8 string to encrypt
/// * `client_public_key_b64` - Client's base64-encoded X25519 public key
///
/// # Returns
/// `E2eEncryptedMessage` containing ciphertext, IV, auth tag, and server public key
///
/// # Example
/// ```rust
/// let encrypted = encrypt_for_client(
///     r#"{"secret": "data"}"#,
///     "base64_client_public_key"
/// )?;
/// ```
pub fn encrypt_for_client(
    plaintext: &str,
    client_public_key_b64: &str,
) -> Result<E2eEncryptedMessage> {
    // Generate ephemeral server keypair
    let (server_secret, server_public) = generate_ephemeral_keypair();

    // Derive shared AES key
    let aes_key = derive_shared_key_ephemeral(server_secret, client_public_key_b64)?;

    // Create AES-256-GCM cipher
    let cipher =
        Aes256Gcm::new_from_slice(&aes_key).map_err(|_| anyhow!("Failed to create AES cipher"))?;

    // Generate random 12-byte IV
    let iv = Aes256Gcm::generate_nonce(&mut AeadOsRng);

    // Encrypt with AES-GCM (ciphertext includes auth tag)
    let ciphertext_with_tag = cipher
        .encrypt(&iv, plaintext.as_bytes())
        .map_err(|_| anyhow!("AES-GCM encryption failed"))?;

    // Split ciphertext and auth tag (last 16 bytes)
    let (ciphertext, auth_tag) = ciphertext_with_tag.split_at(ciphertext_with_tag.len() - 16);

    Ok(E2eEncryptedMessage {
        ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
        iv: URL_SAFE_NO_PAD.encode(iv.as_slice()),
        auth_tag: URL_SAFE_NO_PAD.encode(auth_tag),
        server_public_key: URL_SAFE_NO_PAD.encode(server_public.as_bytes()),
    })
}

// Decryption (Client → Server)

/// Decrypts a message from a client
///
/// Used when the server needs to decrypt client-encrypted requests.
///
/// # Arguments
/// * `encrypted` - The encrypted request from client
/// * `server_secret_key` - Server's static secret key bytes
///
/// # Returns
/// Decrypted plaintext string
pub fn decrypt_from_client(
    encrypted: &E2eEncryptedRequest,
    server_secret_key: &[u8; 32],
) -> Result<String> {
    // Derive shared AES key
    let aes_key = derive_shared_key(server_secret_key, &encrypted.client_public_key)?;

    // Decode components
    let ciphertext = URL_SAFE_NO_PAD
        .decode(&encrypted.ciphertext)
        .map_err(|_| anyhow!("Invalid base64 ciphertext"))?;
    let iv_bytes = URL_SAFE_NO_PAD
        .decode(&encrypted.iv)
        .map_err(|_| anyhow!("Invalid base64 IV"))?;
    let auth_tag = URL_SAFE_NO_PAD
        .decode(&encrypted.auth_tag)
        .map_err(|_| anyhow!("Invalid base64 auth tag"))?;

    if iv_bytes.len() != 12 {
        return Err(anyhow!(
            "Invalid IV length: expected 12, got {}",
            iv_bytes.len()
        ));
    }
    if auth_tag.len() != 16 {
        return Err(anyhow!(
            "Invalid auth tag length: expected 16, got {}",
            auth_tag.len()
        ));
    }

    // Reconstruct ciphertext with tag for aes-gcm
    let mut ciphertext_with_tag = ciphertext;
    ciphertext_with_tag.extend_from_slice(&auth_tag);

    // Create cipher and decrypt
    let cipher =
        Aes256Gcm::new_from_slice(&aes_key).map_err(|_| anyhow!("Failed to create AES cipher"))?;
    let nonce = Nonce::from_slice(&iv_bytes);

    let plaintext = cipher
        .decrypt(nonce, ciphertext_with_tag.as_slice())
        .map_err(|_| anyhow!("AES-GCM decryption failed - invalid auth tag or corrupted data"))?;

    String::from_utf8(plaintext).map_err(|_| anyhow!("Decrypted data is not valid UTF-8"))
}

/// Decrypts a server response (client-side operation, included for testing)
///
/// This mirrors what the client does to decrypt server responses.
///
/// # Arguments
/// * `encrypted` - The encrypted message from server
/// * `client_secret_key` - Client's secret key bytes
///
/// # Returns
/// Decrypted plaintext string
pub fn decrypt_server_response(
    encrypted: &E2eEncryptedMessage,
    client_secret_key: &[u8; 32],
) -> Result<String> {
    // Derive shared AES key using server's public key
    let aes_key = derive_shared_key(client_secret_key, &encrypted.server_public_key)?;

    // Decode components
    let ciphertext = URL_SAFE_NO_PAD
        .decode(&encrypted.ciphertext)
        .map_err(|_| anyhow!("Invalid base64 ciphertext"))?;
    let iv_bytes = URL_SAFE_NO_PAD
        .decode(&encrypted.iv)
        .map_err(|_| anyhow!("Invalid base64 IV"))?;
    let auth_tag = URL_SAFE_NO_PAD
        .decode(&encrypted.auth_tag)
        .map_err(|_| anyhow!("Invalid base64 auth tag"))?;

    if iv_bytes.len() != 12 {
        return Err(anyhow!(
            "Invalid IV length: expected 12, got {}",
            iv_bytes.len()
        ));
    }
    if auth_tag.len() != 16 {
        return Err(anyhow!(
            "Invalid auth tag length: expected 16, got {}",
            auth_tag.len()
        ));
    }

    // Reconstruct ciphertext with tag
    let mut ciphertext_with_tag = ciphertext;
    ciphertext_with_tag.extend_from_slice(&auth_tag);

    // Create cipher and decrypt
    let cipher =
        Aes256Gcm::new_from_slice(&aes_key).map_err(|_| anyhow!("Failed to create AES cipher"))?;
    let nonce = Nonce::from_slice(&iv_bytes);

    let plaintext = cipher
        .decrypt(nonce, ciphertext_with_tag.as_slice())
        .map_err(|_| anyhow!("AES-GCM decryption failed - invalid auth tag or corrupted data"))?;

    String::from_utf8(plaintext).map_err(|_| anyhow!("Decrypted data is not valid UTF-8"))
}

// Utility Functions

/// Encodes a public key to base64 (URL-safe, no padding)
pub fn encode_public_key(key: &[u8; 32]) -> String {
    URL_SAFE_NO_PAD.encode(key)
}

/// Decodes a base64 public key
pub fn decode_public_key(key_b64: &str) -> Result<[u8; 32]> {
    let bytes = URL_SAFE_NO_PAD
        .decode(key_b64)
        .map_err(|_| anyhow!("Invalid base64 public key"))?;

    if bytes.len() != 32 {
        return Err(anyhow!(
            "Invalid public key length: expected 32, got {}",
            bytes.len()
        ));
    }

    bytes
        .try_into()
        .map_err(|_| anyhow!("Failed to convert public key bytes"))
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let kp1 = generate_keypair();
        let kp2 = generate_keypair();

        // Keys should be different
        assert_ne!(kp1.public_key, kp2.public_key);

        // Public key should be valid base64 of 32 bytes
        let decoded = URL_SAFE_NO_PAD.decode(&kp1.public_key).unwrap();
        assert_eq!(decoded.len(), 32);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        // Generate client keypair
        let client_kp = generate_keypair();

        // Encrypt message for client
        let plaintext = r#"{"secret": "sensitive_data", "amount": 1234}"#;
        let encrypted = encrypt_for_client(plaintext, &client_kp.public_key).unwrap();

        // Verify encrypted message structure
        assert!(!encrypted.ciphertext.is_empty());
        assert!(!encrypted.iv.is_empty());
        assert!(!encrypted.auth_tag.is_empty());
        assert!(!encrypted.server_public_key.is_empty());

        // Decrypt on client side
        let decrypted = decrypt_server_response(&encrypted, client_kp.secret_key_bytes()).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_client_to_server_roundtrip() {
        // Generate server and client keypairs
        let server_kp = generate_keypair();
        let _client_kp = generate_keypair();

        // Simulate client encrypting a request
        let plaintext = r#"{"action": "pay", "amount": 5000}"#;

        // Client encrypts using server's public key
        let encrypted = encrypt_for_client(plaintext, &server_kp.public_key).unwrap();

        // Convert to request format
        let request = E2eEncryptedRequest {
            ciphertext: encrypted.ciphertext,
            iv: encrypted.iv,
            auth_tag: encrypted.auth_tag,
            client_public_key: encrypted.server_public_key, // The "server" key is actually client's ephemeral
        };

        // Server decrypts
        let decrypted = decrypt_from_client(&request, server_kp.secret_key_bytes()).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_wrong_key_fails() {
        let client_kp = generate_keypair();
        let wrong_kp = generate_keypair();

        let plaintext = "secret message";
        let encrypted = encrypt_for_client(plaintext, &client_kp.public_key).unwrap();

        // Attempt decryption with wrong key should fail
        let result = decrypt_server_response(&encrypted, wrong_kp.secret_key_bytes());
        assert!(result.is_err());
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let client_kp = generate_keypair();

        let plaintext = "secret message";
        let mut encrypted = encrypt_for_client(plaintext, &client_kp.public_key).unwrap();

        // Tamper with ciphertext
        let mut ciphertext_bytes = URL_SAFE_NO_PAD.decode(&encrypted.ciphertext).unwrap();
        if !ciphertext_bytes.is_empty() {
            ciphertext_bytes[0] ^= 0xFF;
        }
        encrypted.ciphertext = URL_SAFE_NO_PAD.encode(&ciphertext_bytes);

        // Decryption should fail due to auth tag mismatch
        let result = decrypt_server_response(&encrypted, client_kp.secret_key_bytes());
        assert!(result.is_err());
    }

    #[test]
    fn test_forward_secrecy() {
        let client_kp = generate_keypair();
        let plaintext = "same message";

        // Encrypt the same message twice
        let encrypted1 = encrypt_for_client(plaintext, &client_kp.public_key).unwrap();
        let encrypted2 = encrypt_for_client(plaintext, &client_kp.public_key).unwrap();

        // Ciphertexts should be different (different ephemeral keys + IVs)
        assert_ne!(encrypted1.ciphertext, encrypted2.ciphertext);
        assert_ne!(encrypted1.server_public_key, encrypted2.server_public_key);
        assert_ne!(encrypted1.iv, encrypted2.iv);

        // Both should decrypt to the same plaintext
        let decrypted1 =
            decrypt_server_response(&encrypted1, client_kp.secret_key_bytes()).unwrap();
        let decrypted2 =
            decrypt_server_response(&encrypted2, client_kp.secret_key_bytes()).unwrap();

        assert_eq!(decrypted1, plaintext);
        assert_eq!(decrypted2, plaintext);
    }
}
