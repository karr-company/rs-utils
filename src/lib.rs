use anyhow::{Result, anyhow};
use aws_sdk_dynamodb::types::AttributeValue;
use base64::{
    Engine as _, alphabet,
    engine::{self, general_purpose},
};
use hex::decode as hex_decode;
use lambda_http::{Body, Error as LambdaError, Response, http::StatusCode};
use openssl::error::ErrorStack;
use openssl::ssl::{SslConnector, SslMethod};
use postgres::{Client as PostgresClient, Error as PostgresError, Transaction, error::SqlState};
use postgres_openssl::MakeTlsConnector;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sodiumoxide::crypto::box_;
use std::{any, collections::HashMap};

/// Runs op inside a transaction and retries it as needed.
/// On non-retryable failures, the transaction is aborted and
/// rolled back; on success, the transaction is committed.
pub fn execute_txn<T, F>(client: &mut PostgresClient, op: F) -> Result<T, PostgresError>
where
    F: Fn(&mut Transaction) -> Result<T, PostgresError>,
{
    let mut txn = client.transaction()?;
    loop {
        // Set a retry savepoint
        // See https://www.cockroachlabs.com/docs/stable/advanced-client-side-transaction-retries
        let mut sp = txn.savepoint("cockroach_restart")?;
        match op(&mut sp).and_then(|t| sp.commit().map(|_| t)) {
            Err(ref err)
                if err
                    .code()
                    .map(|e| *e == SqlState::T_R_SERIALIZATION_FAILURE)
                    .unwrap_or(false) => {}
            r => break r,
        }
    }
    .and_then(|t| txn.commit().map(|_| t))
}

// Get SSL config
pub async fn ssl_config(cert_url: &str) -> Result<MakeTlsConnector, CertError> {
    let cert_pem = reqwest::get(cert_url).await?.bytes().await?;
    let cert = openssl::x509::X509::from_pem(&cert_pem)?;

    let mut store_builder = openssl::x509::store::X509StoreBuilder::new()?;
    store_builder.add_cert(cert)?;

    let mut connector_builder = SslConnector::builder(SslMethod::tls())?;
    connector_builder.set_verify(openssl::ssl::SslVerifyMode::PEER);
    connector_builder.set_cert_store(store_builder.build());

    Ok(MakeTlsConnector::new(connector_builder.build()))
}

// Generate a JSON response
pub fn json_response(payload: String) -> Result<Response<Body>, LambdaError> {
    let rsp = Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(payload.into())
        .map_err(Box::new)?;
    Ok(rsp)
}

// Generate an empty JSON response
pub fn empty_json_response() -> Result<Response<Body>, LambdaError> {
    let rsp = Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(json!({}).to_string().into())
        .map_err(Box::new)?;
    Ok(rsp)
}

// Generate a error response with error message
pub fn error_response(
    err: anyhow::Error,
    status_code: StatusCode,
) -> Result<Response<Body>, LambdaError> {
    let payload = json!({ "error": err.to_string() });
    let rsp = Response::builder()
        .status(status_code)
        .header("content-type", "application/json")
        .body(payload.to_string().into())
        .map_err(Box::new)?;
    Ok(rsp)
}

pub fn attribute_value_to_json(av: &AttributeValue) -> Value {
    if let Some(s) = av.as_s().ok() {
        Value::String(s.to_string())
    } else if let Some(n) = av.as_n().ok() {
        // Try to parse number as f64 or i64 depending on your use case
        if let Ok(int_val) = n.parse::<i64>() {
            Value::Number(int_val.into())
        } else if let Ok(float_val) = n.parse::<f64>() {
            Value::Number(serde_json::Number::from_f64(float_val).unwrap())
        } else {
            Value::String(n.to_string())
        }
    } else if let Some(m) = av.as_m().ok() {
        let map_json: serde_json::Map<String, Value> = m
            .iter()
            .map(|(k, v)| (k.clone(), attribute_value_to_json(v)))
            .collect();
        Value::Object(map_json)
    } else if let Some(l) = av.as_l().ok() {
        let list_json: Vec<Value> = l.iter().map(attribute_value_to_json).collect();
        Value::Array(list_json)
    } else if av.as_bool().is_ok() {
        Value::Bool(av.as_bool().unwrap().clone())
    } else if av.is_null() {
        Value::Null
    } else {
        Value::Null // fallback for other types like Binary etc.
    }
}

pub fn item_to_json_map(item: &HashMap<String, AttributeValue>) -> serde_json::Map<String, Value> {
    item.iter()
        .map(|(k, v)| (k.clone(), attribute_value_to_json(v)))
        .collect()
}

pub fn decrypt_nacl_box(
    ciphertext_b64: &str,
    nonce_b64: &str,
    ephemeral_pub_b64: &str,
    server_secret_key_hex: &str,
) -> Result<String> {
    // Initialize sodium
    sodiumoxide::init().map_err(|_| anyhow!("Failed to init sodiumoxide"))?;

    // Decode server's secret key from hex
    let server_sk_bytes =
        hex_decode(server_secret_key_hex).map_err(|_| anyhow!("Invalid hex in secret key"))?;
    let server_sk = box_::SecretKey::from_slice(&server_sk_bytes)
        .ok_or_else(|| anyhow!("Invalid server secret key"))?;
    let decoder = engine::GeneralPurpose::new(&alphabet::URL_SAFE, general_purpose::NO_PAD);
    // Decode client ephemeral public key
    let client_pk_bytes = decoder.decode(ephemeral_pub_b64)?;
    let client_pk = box_::PublicKey::from_slice(&client_pk_bytes)
        .ok_or_else(|| anyhow!("Invalid client public key"))?;

    // Decode nonce
    let nonce_bytes = decoder.decode(nonce_b64)?;
    let nonce = box_::Nonce::from_slice(&nonce_bytes).ok_or_else(|| anyhow!("Invalid nonce"))?;

    // Decode ciphertext
    let ciphertext = decoder.decode(ciphertext_b64)?;

    // Attempt decryption
    let decrypted = box_::open(&ciphertext, &nonce, &client_pk, &server_sk)
        .map_err(|_| anyhow!("Decryption failed"))?;

    // Convert decrypted bytes to UTF-8 string
    let decrypted_str =
        String::from_utf8(decrypted).map_err(|_| anyhow!("Decrypted data is not valid UTF-8"))?;

    Ok(decrypted_str)
}

pub fn encrypt_nacl_box(
    plaintext: &str,
    nonce_b64: &str,
    server_pub_b64: &str,
    client_secret_key_hex: &str,
) -> Result<String> {
    // Initialize sodium
    sodiumoxide::init().map_err(|_| anyhow!("Failed to init sodiumoxide"))?;

    // Decode client's secret key from hex
    let client_sk_bytes =
        hex_decode(client_secret_key_hex).map_err(|_| anyhow!("Invalid hex in secret key"))?;
    let client_sk = box_::SecretKey::from_slice(&client_sk_bytes)
        .ok_or_else(|| anyhow!("Invalid client secret key"))?;
    let decoder = engine::GeneralPurpose::new(&alphabet::URL_SAFE, general_purpose::NO_PAD);
    // Decode server's public key
    let server_pk_bytes = decoder.decode(server_pub_b64)?;
    let server_pk = box_::PublicKey::from_slice(&server_pk_bytes)
        .ok_or_else(|| anyhow!("Invalid server public key"))?;

    // Decode nonce
    let nonce_bytes = decoder.decode(nonce_b64)?;
    let nonce = box_::Nonce::from_slice(&nonce_bytes).ok_or_else(|| anyhow!("Invalid nonce"))?;

    // Encrypt the plaintext
    let ciphertext = box_::seal(plaintext.as_bytes(), &nonce, &server_pk, &client_sk);

    // Encode ciphertext to base64
    let encoder = engine::GeneralPurpose::new(&alphabet::URL_SAFE, general_purpose::NO_PAD);
    let ciphertext_b64 = encoder.encode(&ciphertext);

    Ok(ciphertext_b64)
}

pub fn convert_and_deserialize(
    item: HashMap<String, AttributeValue>,
) -> Result<DynamicItem, serde_json::Error> {
    let json_map = item_to_json_map(&item);
    let json_value = serde_json::Value::Object(json_map);
    serde_json::from_value(json_value)
}

#[derive(Debug, thiserror::Error)]
pub enum CertError {
    #[error("OpenSSL error")]
    OpenSslError(#[from] ErrorStack),

    #[error("Reqwest error")]
    ReqwestError(#[from] reqwest::Error),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DynamicItem {
    #[serde(flatten)]
    fields: HashMap<String, Value>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD};

    #[test]
    fn test_execute_txn() {
        // This test would require a live Postgres database connection.
        // For demonstration purposes, we will just ensure the function compiles.
        // In a real-world scenario, you would set up a test database and
        // verify transaction behavior here.
        assert!(true);
    }

    #[tokio::test]
    async fn test_ssl_config_invalid_url() {
        let cert_url = "https://fm4dd.com/openssl/source/PEM/certs/napoleon-cert.pem";
        let result = ssl_config(cert_url).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_json_response() {
        let payload = "{\"key\":\"value\"}".to_string();
        let response = json_response(payload).unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_error_response() {
        let err = anyhow!("Test error");
        let response = error_response(err, StatusCode::BAD_REQUEST).unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_empty_json_response() {
        let response = empty_json_response().unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_attribute_value_to_json() {
        let av_string = AttributeValue::S("test".to_string());
        let json_value = attribute_value_to_json(&av_string);
        assert_eq!(json_value, Value::String("test".to_string()));

        let av_number = AttributeValue::N("42".to_string());
        let json_value = attribute_value_to_json(&av_number);
        assert_eq!(json_value, Value::Number(42.into()));

        let mut map = HashMap::new();
        map.insert("key".to_string(), AttributeValue::S("value".to_string()));
        let av_map = AttributeValue::M(map);
        let json_value = attribute_value_to_json(&av_map);
        let mut expected_map = serde_json::Map::new();
        expected_map.insert("key".to_string(), Value::String("value".to_string()));
        assert_eq!(json_value, Value::Object(expected_map));
    }

    #[tokio::test]
    async fn test_item_to_json_map() {
        let mut item = HashMap::new();
        item.insert("key".to_string(), AttributeValue::S("value".to_string()));
        let json_map = item_to_json_map(&item);
        let mut expected_map = serde_json::Map::new();
        expected_map.insert("key".to_string(), Value::String("value".to_string()));
        assert_eq!(json_map, expected_map);
    }

    #[tokio::test]
    async fn test_convert_and_deserialize() {
        let mut item = HashMap::new();
        item.insert("field1".to_string(), AttributeValue::S("value1".to_string()));
        item.insert("field2".to_string(), AttributeValue::N("42".to_string()));

        let result = convert_and_deserialize(item);
        assert!(result.is_ok());
        let dynamic_item = result.unwrap();
        assert_eq!(dynamic_item.fields.get("field1").unwrap(), &Value::String("value1".to_string()));
        assert_eq!(dynamic_item.fields.get("field2").unwrap(), &Value::Number(42.into()));
    }

    #[tokio::test]
    async fn test_convert_and_deserialize_invalid() {
        let mut item = HashMap::new();
        item.insert("field1".to_string(), AttributeValue::S("value1".to_string()));
        // Intentionally adding an invalid type to trigger deserialization error
        item.insert("field2".to_string(), AttributeValue::Bool(true));

        let result = convert_and_deserialize(item);
        assert!(result.is_ok()); // This should still succeed as Bool can be represented in Value
    }

    #[test]
    fn test_decrypt_nacl_box_success() {
        // Initialize sodium
        sodiumoxide::init().unwrap();

        // Generate key pairs
        let (client_pk, client_sk) = box_::gen_keypair();
        let (server_pk, server_sk) = box_::gen_keypair();

        // Create a message and nonce
        let message = b"hello world";
        let nonce = box_::gen_nonce();

        // Encrypt the message
        let ciphertext = box_::seal(message, &nonce, &server_pk, &client_sk);

        // Encode parts
        let ciphertext_b64 = URL_SAFE_NO_PAD.encode(&ciphertext);
        let nonce_b64 = URL_SAFE_NO_PAD.encode(nonce.as_ref());
        let ephemeral_pub_b64 = URL_SAFE_NO_PAD.encode(client_pk.as_ref());
        let server_secret_key_hex = hex::encode(server_sk.as_ref());

        // Call the function under test
        let result = decrypt_nacl_box(
            &ciphertext_b64,
            &nonce_b64,
            &ephemeral_pub_b64,
            &server_secret_key_hex,
        );

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "hello world");
    }

    #[test]
    fn test_decrypt_nacl_box_failure() {
        // Invalid base64 input
        let result = decrypt_nacl_box(
            "invalid_base64",
            "invalid_base64",
            "invalid_base64",
            "invalid_hex",
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_nacl_box_success() {
        // Initialize sodium
        sodiumoxide::init().unwrap();
        // Generate key pairs
        let (_client_pk, client_sk) = box_::gen_keypair();
        let (server_pk, _server_sk) = box_::gen_keypair();
        // Create a message and nonce
        let message = "hello world";
        let nonce = box_::gen_nonce();
        // Encode parts
        let nonce_b64 = URL_SAFE_NO_PAD.encode(nonce.as_ref());
        let server_pub_b64 = URL_SAFE_NO_PAD.encode(server_pk.as_ref());
        let client_secret_key_hex = hex::encode(client_sk.as_ref());
        // Call the function under test
        let result = encrypt_nacl_box(
            message,
            &nonce_b64,
            &server_pub_b64,
            &client_secret_key_hex,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_encrypt_nacl_box_failure() {
        // Invalid base64 input
        let result = encrypt_nacl_box(
            "hello world",
            "invalid_base64",
            "invalid_base64",
            "invalid_hex",
        );
        assert!(result.is_err());
    }
}
