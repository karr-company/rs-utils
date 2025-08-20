use lambda_http::{Body, Error as LambdaError, Response, http::StatusCode};
use openssl::error::ErrorStack;
use openssl::ssl::{SslConnector, SslMethod};
use postgres::{Client as PostgresClient, Error as PostgresError, Transaction, error::SqlState};
use postgres_openssl::MakeTlsConnector;
use serde_json::json;

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

#[derive(Debug, thiserror::Error)]
pub enum CertError {
    #[error("OpenSSL error")]
    OpenSslError(#[from] ErrorStack),

    #[error("Reqwest error")]
    ReqwestError(#[from] reqwest::Error),
}
