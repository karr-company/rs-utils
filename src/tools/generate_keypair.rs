//! Sodiumoxide Keypair Generator (Developer Tool)
//!
//! This binary is intended for local developer use only.
//!
//! It generates a Curve25519 keypair using sodiumoxide and prints the public key (Base64, URL-safe, no padding)
//! and secret key (hex) to stdout. These keys are used for configuring secure communication in development
//! and testing environments.
//!
//! **Not intended for production or automated deployment.**
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hex;
use sodiumoxide::crypto::box_;

#[cfg(not(tarpaulin_include))]
fn main() {
    sodiumoxide::init().expect("sodium init failed");

    let (pk, sk) = box_::gen_keypair();

    println!(
        "SERVER_PUBLIC_KEY_B64={}",
        URL_SAFE_NO_PAD.encode(pk.as_ref())
    );
    println!("SERVER_SECRET_KEY_HEX={}", hex::encode(sk.as_ref()));
}
