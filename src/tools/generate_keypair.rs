//! Keypair Generator (Developer Tool)
//!
//! This binary generates X25519 keypairs for E2E encryption.
//! Keys are printed in base64 format suitable for environment variables.
//!
//! **For local development and key provisioning only.**

use rs_utils::e2e_crypto::generate_keypair;

#[cfg(not(tarpaulin_include))]
fn main() {
    let keypair = generate_keypair();

    println!("# E2E Encryption Keypair (X25519)");
    println!("# Store the private key securely (env var, secrets manager)");
    println!("# Distribute the public key to clients");
    println!();
    println!("E2E_SERVER_PUBLIC_KEY_B64={}", keypair.public_key);
    println!("E2E_SERVER_PRIVATE_KEY_B64={}", keypair.private_key);
}
