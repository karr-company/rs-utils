//! E2E Encryption Module
//!
//! Provides secure end-to-end encryption using:
//! - X25519 ECDH for key exchange (ephemeral keys per message)
//! - HKDF-SHA256 for key derivation
//! - AES-256-GCM for authenticated encryption
//!
//! This module is NIST-compliant and compatible with Node.js `crypto` module
//! for cross-platform E2E encryption.
//!
//! ## Security Model
//!
//! ```text
//! Client -> Server:
//! 1. Client generates ephemeral X25519 keypair
//! 2. Client computes shared_secret = ECDH(ephemeral_secret, server_public)
//! 3. Client derives AES key = HKDF(shared_secret, salt, info)
//! 4. Client encrypts: ciphertext = AES-GCM(plaintext, key, random_nonce)
//! 5. Client sends: {ciphertext, nonce, ephemeral_public_key}
//! 6. Server computes: shared_secret = ECDH(server_secret, ephemeral_public)
//! 7. Server derives same AES key and decrypts
//! ```
//!
//! ## Example: Basic Encryption/Decryption
//!
//! ```rust,ignore
//! use rs_utils::e2e_crypto::{generate_keypair, encrypt_for_recipient, decrypt_message, HkdfParams};
//!
//! // Server generates static keypair (store private key securely)
//! let server_keys = generate_keypair();
//!
//! // Client encrypts message for server
//! let params = HkdfParams::new("e2e-v1-salt", "e2e-v1-aes-gcm-key");
//! let encrypted = encrypt_for_recipient("Hello server!", &server_keys.public_key, &params).unwrap();
//!
//! // Server decrypts
//! let plaintext = decrypt_message(&encrypted, &server_keys.private_key, &params).unwrap();
//! assert_eq!(plaintext, "Hello server!");
//! ```
//!
//! ## Example: API Key Generation
//!
//! ```rust,ignore
//! use rs_utils::e2e_crypto::{generate_api_key, verify_api_key_secret};
//!
//! let pepper = "secret-pepper-from-env";
//! let bundle = generate_api_key(pepper);
//!
//! // Store in database: bundle.key_id, bundle.hashed_secret
//! // Give to client: bundle.full_key
//!
//! // Later, verify incoming key:
//! let is_valid = verify_api_key_secret(&bundle.secret, pepper, &bundle.hashed_secret);
//! ```

use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, AeadCore, OsRng},
};
use anyhow::{Result, anyhow};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use utoipa::ToSchema;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

const AES_KEY_LENGTH: usize = 32;

// ============ Types ============

/// X25519 keypair for E2E encryption
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct E2eKeyPair {
    /// Base64-encoded public key (32 bytes)
    pub public_key: String,
    /// Base64-encoded private key (32 bytes)
    pub private_key: String,
}

/// Encrypted message with ephemeral public key
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct E2eEncryptedMessage {
    /// Base64-encoded ciphertext (includes auth tag)
    pub ciphertext: String,
    /// Base64-encoded nonce/IV (12 bytes)
    pub nonce: String,
    /// Base64-encoded ephemeral public key (32 bytes)
    pub ephemeral_public_key: String,
}

/// HKDF parameters for key derivation
///
/// These parameters must be identical across all platforms (Rust, Node.js, React Native)
/// for successful encryption/decryption interoperability.
#[derive(Debug, Clone)]
pub struct HkdfParams<'a> {
    /// Salt for HKDF extraction step
    pub salt: &'a [u8],
    /// Info/context for HKDF expansion step
    pub info: &'a [u8],
}

impl<'a> HkdfParams<'a> {
    /// Creates HKDF parameters from string values
    ///
    /// # Arguments
    /// * `salt` - Domain separation salt (e.g., "e2e-v1-salt")
    /// * `info` - Context binding info (e.g., "e2e-v1-aes-gcm-key")
    pub fn new(salt: &'a str, info: &'a str) -> Self {
        Self {
            salt: salt.as_bytes(),
            info: info.as_bytes(),
        }
    }

    /// Creates HKDF parameters from raw byte slices
    pub fn from_bytes(salt: &'a [u8], info: &'a [u8]) -> Self {
        Self { salt, info }
    }
}

/// Generated API key components
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ApiKeyBundle {
    /// Unique key identifier (URL-safe base64, 16 bytes)
    pub key_id: String,
    /// Secret portion (URL-safe base64, 32 bytes)
    pub secret: String,
    /// Full key in format "key_id.secret"
    pub full_key: String,
    /// SHA256 hash of (secret + pepper), hex-encoded
    pub hashed_secret: String,
}

// ============ Key Generation ============

/// Generates a new X25519 keypair for E2E encryption
///
/// The keypair should be generated once for the server and stored securely.
/// The public key can be distributed to clients.
///
/// # Returns
/// An `E2eKeyPair` with base64-encoded public and private keys
///
/// # Example
/// ```rust,ignore
/// use rs_utils::e2e_crypto::generate_keypair;
///
/// let keypair = generate_keypair();
/// println!("Public key: {}", keypair.public_key);
/// // Store keypair.private_key securely (env var, secrets manager)
/// ```
pub fn generate_keypair() -> E2eKeyPair {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);

    E2eKeyPair {
        public_key: URL_SAFE_NO_PAD.encode(public.as_bytes()),
        private_key: URL_SAFE_NO_PAD.encode(secret.as_bytes()),
    }
}

// ============ Encryption ============

/// Encrypts a message for a recipient using their public key
///
/// Uses ephemeral X25519 key exchange, HKDF-SHA256, and AES-256-GCM.
/// Each call generates a new ephemeral keypair for forward secrecy.
///
/// # Arguments
/// * `plaintext` - UTF-8 string to encrypt
/// * `recipient_public_key_b64` - Recipient's base64-encoded X25519 public key
/// * `hkdf_params` - HKDF salt and info parameters
///
/// # Returns
/// An `E2eEncryptedMessage` containing ciphertext, nonce, and ephemeral public key
///
/// # Errors
/// Returns an error if the public key is invalid or encryption fails
///
/// # Example
/// ```rust,ignore
/// use rs_utils::e2e_crypto::{encrypt_for_recipient, HkdfParams};
///
/// let params = HkdfParams::new("e2e-v1-salt", "e2e-v1-aes-gcm-key");
/// let encrypted = encrypt_for_recipient(
///     "Hello, World!",
///     &server_public_key,
///     &params
/// )?;
/// ```
pub fn encrypt_for_recipient(
    plaintext: &str,
    recipient_public_key_b64: &str,
    hkdf_params: &HkdfParams,
) -> Result<E2eEncryptedMessage> {
    // Decode recipient's public key
    let recipient_pk_bytes = URL_SAFE_NO_PAD
        .decode(recipient_public_key_b64)
        .map_err(|_| anyhow!("Invalid recipient public key base64"))?;

    let recipient_pk_array: [u8; 32] = recipient_pk_bytes
        .try_into()
        .map_err(|_| anyhow!("Recipient public key must be 32 bytes"))?;

    let recipient_public_key = PublicKey::from(recipient_pk_array);

    // Generate ephemeral keypair
    let ephemeral_secret = EphemeralSecret::random_from_rng(OsRng);
    let ephemeral_public = PublicKey::from(&ephemeral_secret);

    // ECDH -> shared secret
    let shared_secret = ephemeral_secret.diffie_hellman(&recipient_public_key);

    // HKDF -> AES key
    let aes_key = derive_aes_key(shared_secret.as_bytes(), hkdf_params)?;

    // AES-256-GCM encrypt
    let cipher = Aes256Gcm::new_from_slice(&aes_key)
        .map_err(|_| anyhow!("Failed to create AES cipher"))?;

    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_bytes())
        .map_err(|_| anyhow!("Encryption failed"))?;

    Ok(E2eEncryptedMessage {
        ciphertext: URL_SAFE_NO_PAD.encode(&ciphertext),
        nonce: URL_SAFE_NO_PAD.encode(nonce),
        ephemeral_public_key: URL_SAFE_NO_PAD.encode(ephemeral_public.as_bytes()),
    })
}

/// Encrypts raw bytes for a recipient using their public key
///
/// Same as `encrypt_for_recipient` but accepts raw bytes instead of a string.
///
/// # Arguments
/// * `plaintext` - Raw bytes to encrypt
/// * `recipient_public_key_b64` - Recipient's base64-encoded X25519 public key
/// * `hkdf_params` - HKDF salt and info parameters
pub fn encrypt_bytes_for_recipient(
    plaintext: &[u8],
    recipient_public_key_b64: &str,
    hkdf_params: &HkdfParams,
) -> Result<E2eEncryptedMessage> {
    let recipient_pk_bytes = URL_SAFE_NO_PAD
        .decode(recipient_public_key_b64)
        .map_err(|_| anyhow!("Invalid recipient public key base64"))?;

    let recipient_pk_array: [u8; 32] = recipient_pk_bytes
        .try_into()
        .map_err(|_| anyhow!("Recipient public key must be 32 bytes"))?;

    let recipient_public_key = PublicKey::from(recipient_pk_array);

    let ephemeral_secret = EphemeralSecret::random_from_rng(OsRng);
    let ephemeral_public = PublicKey::from(&ephemeral_secret);

    let shared_secret = ephemeral_secret.diffie_hellman(&recipient_public_key);
    let aes_key = derive_aes_key(shared_secret.as_bytes(), hkdf_params)?;

    let cipher = Aes256Gcm::new_from_slice(&aes_key)
        .map_err(|_| anyhow!("Failed to create AES cipher"))?;

    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|_| anyhow!("Encryption failed"))?;

    Ok(E2eEncryptedMessage {
        ciphertext: URL_SAFE_NO_PAD.encode(&ciphertext),
        nonce: URL_SAFE_NO_PAD.encode(nonce),
        ephemeral_public_key: URL_SAFE_NO_PAD.encode(ephemeral_public.as_bytes()),
    })
}

// ============ Decryption ============

/// Decrypts a message using the recipient's private key
///
/// # Arguments
/// * `encrypted` - The encrypted message containing ciphertext, nonce, and ephemeral public key
/// * `recipient_private_key_b64` - Recipient's base64-encoded X25519 private key
/// * `hkdf_params` - HKDF salt and info parameters (must match encryption)
///
/// # Returns
/// The decrypted UTF-8 string
///
/// # Errors
/// Returns an error if decryption fails (wrong key, tampered data, or mismatched HKDF params)
///
/// # Example
/// ```rust,ignore
/// use rs_utils::e2e_crypto::{decrypt_message, HkdfParams};
///
/// let params = HkdfParams::new("e2e-v1-salt", "e2e-v1-aes-gcm-key");
/// let plaintext = decrypt_message(&encrypted, &server_private_key, &params)?;
/// ```
pub fn decrypt_message(
    encrypted: &E2eEncryptedMessage,
    recipient_private_key_b64: &str,
    hkdf_params: &HkdfParams,
) -> Result<String> {
    let decrypted_bytes = decrypt_message_bytes(encrypted, recipient_private_key_b64, hkdf_params)?;

    String::from_utf8(decrypted_bytes)
        .map_err(|_| anyhow!("Decrypted data is not valid UTF-8"))
}

/// Decrypts a message to raw bytes using the recipient's private key
///
/// Same as `decrypt_message` but returns raw bytes instead of a string.
pub fn decrypt_message_bytes(
    encrypted: &E2eEncryptedMessage,
    recipient_private_key_b64: &str,
    hkdf_params: &HkdfParams,
) -> Result<Vec<u8>> {
    // Decode recipient's private key
    let recipient_sk_bytes = URL_SAFE_NO_PAD
        .decode(recipient_private_key_b64)
        .map_err(|_| anyhow!("Invalid recipient private key base64"))?;

    let recipient_sk_array: [u8; 32] = recipient_sk_bytes
        .try_into()
        .map_err(|_| anyhow!("Recipient private key must be 32 bytes"))?;

    let recipient_secret = StaticSecret::from(recipient_sk_array);

    // Decode ephemeral public key
    let ephemeral_pk_bytes = URL_SAFE_NO_PAD
        .decode(&encrypted.ephemeral_public_key)
        .map_err(|_| anyhow!("Invalid ephemeral public key base64"))?;

    let ephemeral_pk_array: [u8; 32] = ephemeral_pk_bytes
        .try_into()
        .map_err(|_| anyhow!("Ephemeral public key must be 32 bytes"))?;

    let ephemeral_public_key = PublicKey::from(ephemeral_pk_array);

    // ECDH -> shared secret
    let shared_secret = recipient_secret.diffie_hellman(&ephemeral_public_key);

    // HKDF -> AES key
    let aes_key = derive_aes_key(shared_secret.as_bytes(), hkdf_params)?;

    // Decode ciphertext and nonce
    let ciphertext = URL_SAFE_NO_PAD
        .decode(&encrypted.ciphertext)
        .map_err(|_| anyhow!("Invalid ciphertext base64"))?;

    let nonce_bytes = URL_SAFE_NO_PAD
        .decode(&encrypted.nonce)
        .map_err(|_| anyhow!("Invalid nonce base64"))?;

    let nonce = Nonce::from_slice(&nonce_bytes);

    // AES-256-GCM decrypt
    let cipher = Aes256Gcm::new_from_slice(&aes_key)
        .map_err(|_| anyhow!("Failed to create AES cipher"))?;

    cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| anyhow!("Decryption failed - invalid ciphertext or authentication tag"))
}

/// Derives an AES-256 key from a shared secret using HKDF-SHA256
fn derive_aes_key(shared_secret: &[u8], params: &HkdfParams) -> Result<[u8; AES_KEY_LENGTH]> {
    let hk = Hkdf::<Sha256>::new(Some(params.salt), shared_secret);
    let mut aes_key = [0u8; AES_KEY_LENGTH];

    hk.expand(params.info, &mut aes_key)
        .map_err(|_| anyhow!("HKDF expansion failed"))?;

    Ok(aes_key)
}

// ============ API Key Generation ============

/// Generates a new API key with ID, secret, and peppered hash
///
/// The key format is `{key_id}.{secret}` where:
/// - `key_id`: 16 random bytes, URL-safe base64 encoded
/// - `secret`: 32 random bytes, URL-safe base64 encoded
/// - `hashed_secret`: SHA256(secret + pepper), hex encoded
///
/// # Arguments
/// * `pepper` - Secret pepper value (from environment/secrets manager)
///
/// # Returns
/// An `ApiKeyBundle` containing all key components
///
/// # Example
/// ```rust,ignore
/// use rs_utils::e2e_crypto::generate_api_key;
///
/// let pepper = std::env::var("AUTH_KEY_PEPPER").unwrap();
/// let bundle = generate_api_key(&pepper);
///
/// // Store in database:
/// // - Id: bundle.key_id
/// // - Hashed: bundle.hashed_secret
/// // - Status: "ACTIVE"
///
/// // Give to client:
/// // - bundle.full_key
/// ```
pub fn generate_api_key(pepper: &str) -> ApiKeyBundle {
    // Generate random bytes for key_id (16 bytes) and secret (32 bytes)
    let mut key_id_bytes = [0u8; 16];
    let mut secret_bytes = [0u8; 32];

    getrandom::fill(&mut key_id_bytes).expect("Failed to generate random bytes for key_id");
    getrandom::fill(&mut secret_bytes).expect("Failed to generate random bytes for secret");

    let key_id = URL_SAFE_NO_PAD.encode(key_id_bytes);
    let secret = URL_SAFE_NO_PAD.encode(secret_bytes);

    // Hash: SHA256(secret + pepper)
    let hashed_secret = hash_api_key_secret(&secret, pepper);

    let full_key = format!("{}.{}", key_id, secret);

    ApiKeyBundle {
        key_id,
        secret,
        full_key,
        hashed_secret,
    }
}

/// Hashes an API key secret with a pepper using SHA256
///
/// Used for storing and verifying API keys.
///
/// # Arguments
/// * `secret` - The secret portion of the API key
/// * `pepper` - Secret pepper value (must be consistent)
///
/// # Returns
/// Hex-encoded SHA256 hash
pub fn hash_api_key_secret(secret: &str, pepper: &str) -> String {
    let input = format!("{}{}", secret, pepper);
    let hash = Sha256::digest(input.as_bytes());
    hex::encode(hash)
}

/// Verifies an API key secret against a stored hash
///
/// Uses constant-time comparison to prevent timing attacks.
///
/// # Arguments
/// * `secret` - The secret portion of the API key (from client request)
/// * `pepper` - Secret pepper value
/// * `stored_hash` - The hex-encoded hash stored in the database
///
/// # Returns
/// `true` if the secret matches the stored hash
///
/// # Example
/// ```rust,ignore
/// use rs_utils::e2e_crypto::verify_api_key_secret;
///
/// // In your authorizer:
/// let is_valid = verify_api_key_secret(auth_key_secret, &pepper, &stored_hash);
/// if !is_valid {
///     return Err("Invalid API key");
/// }
/// ```
pub fn verify_api_key_secret(secret: &str, pepper: &str, stored_hash: &str) -> bool {
    let computed_hash = hash_api_key_secret(secret, pepper);
    // Constant-time comparison to prevent timing attacks
    constant_time_eq(computed_hash.as_bytes(), stored_hash.as_bytes())
}

/// Parses an API key in "key_id.secret" format
///
/// # Arguments
/// * `full_key` - The full API key string
///
/// # Returns
/// A tuple of (key_id, secret) if valid, or an error
///
/// # Example
/// ```rust,ignore
/// use rs_utils::e2e_crypto::parse_api_key;
///
/// let (key_id, secret) = parse_api_key("abc123.xyz789")?;
/// ```
pub fn parse_api_key(full_key: &str) -> Result<(&str, &str)> {
    let mut parts = full_key.splitn(2, '.');

    let key_id = parts
        .next()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("Invalid API key format: missing key_id"))?;

    let secret = parts
        .next()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("Invalid API key format: missing secret"))?;

    Ok((key_id, secret))
}

/// Constant-time byte comparison to prevent timing attacks
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

// ============ Tests ============

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SALT: &str = "e2e-v1-salt";
    const TEST_INFO: &str = "e2e-v1-aes-gcm-key";

    #[test]
    fn test_keypair_generation() {
        let keypair = generate_keypair();

        // Verify base64 decodes to 32 bytes
        let pk_bytes = URL_SAFE_NO_PAD.decode(&keypair.public_key).unwrap();
        let sk_bytes = URL_SAFE_NO_PAD.decode(&keypair.private_key).unwrap();

        assert_eq!(pk_bytes.len(), 32);
        assert_eq!(sk_bytes.len(), 32);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let params = HkdfParams::new(TEST_SALT, TEST_INFO);
        let recipient = generate_keypair();
        let plaintext = "Hello, secure world! 🔐";

        let encrypted = encrypt_for_recipient(plaintext, &recipient.public_key, &params).unwrap();

        // Verify encrypted message structure
        assert!(!encrypted.ciphertext.is_empty());
        assert!(!encrypted.nonce.is_empty());
        assert!(!encrypted.ephemeral_public_key.is_empty());

        let decrypted = decrypt_message(&encrypted, &recipient.private_key, &params).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_bytes_roundtrip() {
        let params = HkdfParams::new(TEST_SALT, TEST_INFO);
        let recipient = generate_keypair();
        let plaintext: Vec<u8> = vec![0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD];

        let encrypted =
            encrypt_bytes_for_recipient(&plaintext, &recipient.public_key, &params).unwrap();

        let decrypted =
            decrypt_message_bytes(&encrypted, &recipient.private_key, &params).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_different_hkdf_params_fail_decrypt() {
        let encrypt_params = HkdfParams::new("salt-v1", "info-v1");
        let decrypt_params = HkdfParams::new("salt-v2", "info-v2");

        let recipient = generate_keypair();
        let plaintext = "Should fail to decrypt";

        let encrypted =
            encrypt_for_recipient(plaintext, &recipient.public_key, &encrypt_params).unwrap();

        let result = decrypt_message(&encrypted, &recipient.private_key, &decrypt_params);

        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_key_fails_decrypt() {
        let params = HkdfParams::new(TEST_SALT, TEST_INFO);
        let recipient = generate_keypair();
        let wrong_recipient = generate_keypair();
        let plaintext = "Secret message";

        let encrypted = encrypt_for_recipient(plaintext, &recipient.public_key, &params).unwrap();

        let result = decrypt_message(&encrypted, &wrong_recipient.private_key, &params);

        assert!(result.is_err());
    }

    #[test]
    fn test_ephemeral_keys_differ() {
        let params = HkdfParams::new(TEST_SALT, TEST_INFO);
        let recipient = generate_keypair();

        let encrypted1 = encrypt_for_recipient("msg1", &recipient.public_key, &params).unwrap();
        let encrypted2 = encrypt_for_recipient("msg2", &recipient.public_key, &params).unwrap();

        // Each encryption should use different ephemeral keys
        assert_ne!(
            encrypted1.ephemeral_public_key,
            encrypted2.ephemeral_public_key
        );
        assert_ne!(encrypted1.nonce, encrypted2.nonce);
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let params = HkdfParams::new(TEST_SALT, TEST_INFO);
        let recipient = generate_keypair();

        let mut encrypted =
            encrypt_for_recipient("original message", &recipient.public_key, &params).unwrap();

        // Tamper with ciphertext
        let mut ciphertext_bytes = URL_SAFE_NO_PAD.decode(&encrypted.ciphertext).unwrap();
        ciphertext_bytes[0] ^= 0xFF;
        encrypted.ciphertext = URL_SAFE_NO_PAD.encode(&ciphertext_bytes);

        let result = decrypt_message(&encrypted, &recipient.private_key, &params);

        assert!(result.is_err());
    }

    #[test]
    fn test_api_key_generation() {
        let pepper = "test-pepper-value";
        let bundle = generate_api_key(pepper);

        // Verify structure
        assert!(!bundle.key_id.is_empty());
        assert!(!bundle.secret.is_empty());
        assert_eq!(
            bundle.full_key,
            format!("{}.{}", bundle.key_id, bundle.secret)
        );

        // Verify key_id is 16 bytes base64
        let key_id_bytes = URL_SAFE_NO_PAD.decode(&bundle.key_id).unwrap();
        assert_eq!(key_id_bytes.len(), 16);

        // Verify secret is 32 bytes base64
        let secret_bytes = URL_SAFE_NO_PAD.decode(&bundle.secret).unwrap();
        assert_eq!(secret_bytes.len(), 32);

        // Verify hash is valid hex (64 chars for SHA256)
        assert_eq!(bundle.hashed_secret.len(), 64);
        assert!(bundle.hashed_secret.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_api_key_verification() {
        let pepper = "production-pepper";
        let bundle = generate_api_key(pepper);

        // Correct verification
        assert!(verify_api_key_secret(
            &bundle.secret,
            pepper,
            &bundle.hashed_secret
        ));

        // Wrong pepper fails
        assert!(!verify_api_key_secret(
            &bundle.secret,
            "wrong-pepper",
            &bundle.hashed_secret
        ));

        // Wrong secret fails
        assert!(!verify_api_key_secret(
            "wrong-secret",
            pepper,
            &bundle.hashed_secret
        ));
    }

    #[test]
    fn test_hash_consistency() {
        let pepper = "my-pepper";
        let secret = "my-secret";

        let hash1 = hash_api_key_secret(secret, pepper);
        let hash2 = hash_api_key_secret(secret, pepper);

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_parse_api_key_valid() {
        let (key_id, secret) = parse_api_key("abc123.xyz789secret").unwrap();
        assert_eq!(key_id, "abc123");
        assert_eq!(secret, "xyz789secret");
    }

    #[test]
    fn test_parse_api_key_with_dots_in_secret() {
        let (key_id, secret) = parse_api_key("keyid.secret.with.dots").unwrap();
        assert_eq!(key_id, "keyid");
        assert_eq!(secret, "secret.with.dots");
    }

    #[test]
    fn test_parse_api_key_invalid() {
        assert!(parse_api_key("no-dot-here").is_err());
        assert!(parse_api_key(".nosecret").is_err());
        assert!(parse_api_key("nokeyid.").is_err());
        assert!(parse_api_key("").is_err());
    }

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(!constant_time_eq(b"hello", b"world"));
        assert!(!constant_time_eq(b"hello", b"hell"));
        assert!(!constant_time_eq(b"", b"x"));
        assert!(constant_time_eq(b"", b""));
    }
}
