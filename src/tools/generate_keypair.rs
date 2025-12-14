use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hex;
use sodiumoxide::crypto::box_;

fn main() {
    sodiumoxide::init().expect("sodium init failed");

    let (pk, sk) = box_::gen_keypair();

    println!(
        "SERVER_PUBLIC_KEY_B64={}",
        URL_SAFE_NO_PAD.encode(pk.as_ref())
    );
    println!("SERVER_SECRET_KEY_HEX={}", hex::encode(sk.as_ref()));
}
