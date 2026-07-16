//! # rs-utils
//!
//! Reusable Rust helpers for Lambda, DynamoDB, cryptography, and validation.
//!
//! ## Modules
//! - [`e2e_crypto`]: **Recommended** - Secure E2E encryption (X25519 + AES-256-GCM, NIST-compliant)
//! - [`json_utils`]: JSON helpers for Lambda/API and DynamoDB conversions
//! - [`validation_utils`]: Email, phone, and JWT validation helpers
//! - [`sst_resources`]: Typed SST resource definitions (Table, Bucket, etc.)
//!
//! ## Usage
//! Import the desired helpers or types from the crate root:
//!
//! ```rust
//! use rs_utils::{encrypt_for_recipient, decrypt_message, HkdfParams, is_valid_email, Table};
//! ```
//!
//! ## Migration from `crypto_box` to `e2e_crypto`
//!
//! The `crypto_box` module is deprecated. Migrate to `e2e_crypto` for:
//! - NIST-compliant encryption (AES-256-GCM)
//! - Forward secrecy (ephemeral keys per message)
//! - Cross-platform compatibility (Node.js, React Native)
//!
//! ## Notes
//! - The `cockroach_utils` module is not exported and is for legacy use only.
//! - The `generate_keypair` binary is for local developer use.

// Secure E2E encryption module (recommended)
#[cfg(feature = "e2e")]
pub mod e2e_crypto;

#[cfg(feature = "e2e")]
pub use e2e_crypto::{
    ApiKeyBundle, E2eEncryptedMessage, E2eKeyPair, HkdfParams,
    decrypt_message, decrypt_message_bytes,
    encrypt_bytes_for_recipient, encrypt_for_recipient,
    generate_api_key, generate_keypair as e2e_generate_keypair,
    hash_api_key_secret, parse_api_key, verify_api_key_secret,
};

#[cfg(feature = "json")]
pub mod json_utils;
#[cfg(feature = "json")]
pub use json_utils::{
    attribute_value_to_json, convert_and_deserialize, empty_json_response, error_response,
    item_to_json_map, json_response, UploadWithFields
};

#[cfg(feature = "jwt")]
pub mod validation_utils;
#[cfg(feature = "jwt")]
pub use validation_utils::{
    AppleTokenClaims, AuthError, GoogleTokenClaims, is_valid_email, is_valid_phone_number,
    verify_apple_id_token, verify_cognito_id_token, verify_google_id_token, verify_google_access_token,
};

#[cfg(feature = "sst")]
pub mod sst_resources;
#[cfg(feature = "sst")]
pub use sst_resources::{
    Bucket, Email, Function, IdentityPool, Queue, Secret, StepFunction, Table, Topic, UserPool, UserPoolClient,
};

#[derive(Debug)]
pub enum TokenLabel {
    Critical,
    Soft,
}

mod stoplist;
mod token_map;

#[cfg(feature = "ai")]
pub mod prompt_utils;
#[cfg(feature = "ai")]
pub use prompt_utils::safe_prompt;

#[cfg(feature = "vehicle")]
pub mod vehicle_utils;
#[cfg(feature = "vehicle")]
pub use vehicle_utils::{
    Condition, ResultType, ResultValue, Rule, RuleEngine, ScannedVehicleFine, Vehicle,
};