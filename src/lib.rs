//! # rs-utils
//!
//! Reusable Rust helpers for Lambda, DynamoDB, cryptography, and validation.
//!
//! ## Modules
//! - [`crypto_box`]: End-to-end encryption utilities (Curve25519 + XSalsa20 + Poly1305)
//! - [`json_utils`]: JSON helpers for Lambda/API and DynamoDB conversions
//! - [`validation_utils`]: Email, phone, and JWT validation helpers
//! - [`sst_resources`]: Typed SST resource definitions (Table, Bucket, etc.)
//!
//! ## Usage
//! Import the desired helpers or types from the crate root:
//!
//! ```rust
//! use rs_utils::{encrypt_box, is_valid_email, Table};
//! ```
//!
//! ## Notes
//! - The `cockroach_utils` module is not exported and is for legacy use only.
//! - The `generate_keypair` binary is for local developer use.
pub mod crypto_box;

pub use crypto_box::{
    EncryptedEphemeralMessage, EncryptedMessage, decrypt_box, encrypt_box, encrypt_ephemeral_box,
    gen_nonce_b64,
};

pub mod json_utils;

pub use json_utils::{
    attribute_value_to_json, convert_and_deserialize, empty_json_response, error_response,
    item_to_json_map, json_response,
};

pub mod validation_utils;

pub use validation_utils::{is_valid_email, is_valid_phone_number, verify_apple_id_token, verify_google_id_token, AuthError, AppleTokenClaims, GoogleTokenClaims};

pub mod sst_resources;

pub use sst_resources::{Bucket, Table, Secret, Queue, UserPool, UserPoolClient, IdentityPool, Email, Topic};