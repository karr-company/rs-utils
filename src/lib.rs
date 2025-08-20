use aws_sdk_dynamodb::types::AttributeValue;
use lambda_http::{Body, Error as LambdaError, Response, http::StatusCode};
use openssl::error::ErrorStack;
use openssl::ssl::{SslConnector, SslMethod};
use postgres::{Client as PostgresClient, Error as PostgresError, Transaction, error::SqlState};
use postgres_openssl::MakeTlsConnector;
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::HashMap;

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
pub fn error_response<E: std::error::Error>(
    err: E,
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

#[derive(Debug, thiserror::Error)]
pub enum CertError {
    #[error("OpenSSL error")]
    OpenSslError(#[from] ErrorStack),

    #[error("Reqwest error")]
    ReqwestError(#[from] reqwest::Error),
}

#[derive(Debug, Deserialize)]
pub struct DynamicItem {
    #[serde(flatten)]
    fields: HashMap<String, Value>,
}
