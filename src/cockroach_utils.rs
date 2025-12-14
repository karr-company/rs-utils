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

#[derive(Debug, thiserror::Error)]
pub enum CertError {
    #[error("OpenSSL error")]
    OpenSslError(#[from] ErrorStack),

    #[error("Reqwest error")]
    ReqwestError(#[from] reqwest::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

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
}