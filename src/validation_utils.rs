//! Validation Utilities: Email, Phone, and JWT
//!
//! This module provides:
//! - Strict email and phone number validation helpers
//! - Google and Apple ID token verification (with JWKS caching)
//! - Strongly-typed claims for Apple and Google ID tokens
//!
//! ## Features
//! - Email validation: Enforces RFC-like rules, rejects IPs and malformed addresses
//! - Phone validation: E.164 format checking
//! - JWT verification: Validates signature, issuer, audience, and expiration for Google/Apple
//! - JWKS caching: Reduces network calls for public key retrieval
//!
//! ## Example
//! ```rust
//! use rs_utils::is_valid_email;
//! assert!(is_valid_email("user@example.com"));
//! ```
use jsonwebtoken::{
    Algorithm, DecodingKey, Validation, decode, decode_header, errors::ErrorKind, jwk::JwkSet,
};
use serde::{Deserialize, Serialize};
use std::{
    sync::OnceLock,
    time::{Duration, Instant},
};
use thiserror::Error;

/// Errors that can occur during authentication and token validation.
#[derive(Debug, Error, PartialEq)]
pub enum AuthError {
    #[error("Invalid token")]
    InvalidToken,

    #[error("Token expired")]
    Expired,

    #[error("Invalid audience")]
    InvalidAudience,

    #[error("Invalid issuer")]
    InvalidIssuer,

    #[error("Key fetch failed")]
    KeyFetch,

    #[error("JWT error")]
    Jwt(#[from] jsonwebtoken::errors::Error),
}

/// Claims extracted from an Apple ID token.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AppleTokenClaims {
    pub aud: Option<String>,
    pub email: Option<String>,
    pub email_verified: Option<bool>,
    pub exp: Option<usize>,
    pub iat: Option<usize>,
    pub is_private_email: Option<bool>,
    pub iss: Option<String>,
    pub nonce: Option<String>,
    pub nonce_supported: Option<bool>,
    pub real_user_status: Option<u8>,
    pub sub: Option<String>,
    pub transfer_sub: Option<String>,
}

/// Claims extracted from a Google ID token.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GoogleTokenClaims {
    pub aud: Option<String>,
    pub email: Option<String>,
    pub email_verified: Option<bool>,
    pub exp: Option<usize>,
    pub family_name: Option<String>,
    pub given_name: Option<String>,
    pub iat: Option<usize>,
    pub iss: Option<String>,
    pub name: Option<String>,
    pub picture: Option<String>,
    pub sub: Option<String>,
}

/// In-memory cache for JWKS (JSON Web Key Set) with timestamp.
struct JwksCache {
    keys: JwkSet,
    fetched_at: Instant,
}

/// In-memory cache for Apple's JWKS (JSON Web Key Set).
static APPLE_JWKS: OnceLock<JwksCache> = OnceLock::new();

/// Apple JWKS endpoint URL.
static APPLE_JWKS_URL: &str = "https://account.apple.com/auth/keys";

/// List of valid Apple token issuers.
static APPLE_ISSUERS: [&str; 4] = [
    "https://appleid.apple.com",
    "appleid.apple.com",
    "https://accounts.apple.com",
    "accounts.apple.com",
];

/// In-memory cache for Google's JWKS (JSON Web Key Set).
static GOOGLE_JWKS: OnceLock<JwksCache> = OnceLock::new();

/// Google JWKS endpoint URL.
static GOOGLE_JWKS_URL: &str = "https://www.googleapis.com/oauth2/v3/certs";

/// List of valid Google token issuers.
static GOOGLE_ISSUERS: [&str; 2] = ["https://accounts.google.com", "accounts.google.com"];

/// Fetches and caches Apple's JWKS (JSON Web Key Set).
async fn get_apple_jwks() -> Result<JwkSet, AuthError> {
    if let Some(lock) = APPLE_JWKS.get() {
        // Check if cached keys are still valid
        if lock.fetched_at.elapsed() < Duration::from_secs(5 * 60) {
            return Ok(lock.keys.clone());
        }
    }

    let jwks: JwkSet = reqwest::get(APPLE_JWKS_URL)
        .await
        .map_err(|_| AuthError::KeyFetch)?
        .json()
        .await
        .map_err(|_| AuthError::KeyFetch)?;

    APPLE_JWKS
        .set(JwksCache {
            keys: jwks.clone(),
            fetched_at: Instant::now(),
        })
        .ok();
    Ok(jwks)
}

/// Fetches and caches Google's JWKS (JSON Web Key Set).
async fn get_google_jwks() -> Result<JwkSet, AuthError> {
    if let Some(lock) = GOOGLE_JWKS.get() {
        // Check if cached keys are still valid
        if lock.fetched_at.elapsed() < Duration::from_secs(5 * 60) {
            return Ok(lock.keys.clone());
        }
    }

    let jwks: JwkSet = reqwest::get(GOOGLE_JWKS_URL)
        .await
        .map_err(|_| AuthError::KeyFetch)?
        .json()
        .await
        .map_err(|_| AuthError::KeyFetch)?;

    GOOGLE_JWKS
        .set(JwksCache {
            keys: jwks.clone(),
            fetched_at: Instant::now(),
        })
        .ok();
    Ok(jwks)
}

/// Validates an email address format with strict requirements:
///
/// - Local part allows: alphanumeric, periods, hyphens, underscores, plus signs
/// - No consecutive dots in local part
/// - Local part cannot start or end with a dot
/// - Domain part cannot be an IP address (IPv4, IPv6, or bracketed)
/// - Domain must contain at least one dot and only valid characters
///
/// # Arguments
/// * `email_address` - The email address to validate
///
/// # Returns
/// `true` if the email address is valid, `false` otherwise
pub fn is_valid_email(email_address: &str) -> bool {
    // Split on @ to get local and domain parts
    let parts: Vec<&str> = email_address.split('@').collect();
    if parts.len() != 2 {
        return false;
    }

    let local_part = parts[0];
    let domain_part = parts[1];

    // Validate local part
    // 1. Contains only allowed characters: alphanumeric, period, hyphen, underscore, plus
    let local_regex = regex::Regex::new(r"^[A-Za-z0-9._+\-]+$").unwrap();
    if !local_regex.is_match(local_part) {
        return false;
    }

    // 2. Does not start with a dot
    if local_part.starts_with('.') {
        return false;
    }

    // 3. Does not end with a dot
    if local_part.ends_with('.') {
        return false;
    }

    // 4. Does not contain consecutive dots
    if local_part.contains("..") {
        return false;
    }

    // Validate domain part
    // 1. Reject any format of number.number.number.number (including malformed IP addresses)
    let numeric_format_regex = regex::Regex::new(r"^\d+(\.\d+)+$").unwrap();
    if numeric_format_regex.is_match(domain_part) {
        return false;
    }

    // 2. Reject bracketed IPv4 addresses ([123.123.123.123])
    let bracket_ipv4_regex = regex::Regex::new(r"^\[\d+(\.\d+)+\]$").unwrap();
    if bracket_ipv4_regex.is_match(domain_part) {
        return false;
    }

    // 3. Reject IPv6 addresses ([IPv6:...])
    let ipv6_regex = regex::Regex::new(r"^\[IPv6:[^\]]+\]$").unwrap();
    if ipv6_regex.is_match(domain_part) {
        return false;
    }

    // 4. Domain contains only valid characters
    let domain_regex = regex::Regex::new(r"^[A-Za-z0-9.\-]+$").unwrap();
    if !domain_regex.is_match(domain_part) {
        return false;
    }

    // 5. Does not start or end with a dot or hyphen
    if domain_part.starts_with('.') || domain_part.ends_with('.') {
        return false;
    }
    if domain_part.starts_with('-') || domain_part.ends_with('-') {
        return false;
    }

    // 6. Contains at least one dot (for valid TLD)
    if !domain_part.contains('.') {
        return false;
    }

    // 7. No consecutive dots in domain part
    if domain_part.contains("..") {
        return false;
    }

    true
}

/// Validates a phone number in E.164 format.
///
/// # Arguments
/// * `phone_number` - The phone number to validate (should start with '+')
///
/// # Returns
/// `true` if the phone number is valid E.164, `false` otherwise
pub fn is_valid_phone_number(phone_number: &str) -> bool {
    let e164_regex = regex::Regex::new(r"^\+(?:[0-9]){6,14}[0-9]$").unwrap();
    e164_regex.is_match(phone_number)
}

/// Verifies a Google ID token and returns its claims if valid.
///
/// # Arguments
/// * `id_token` - The JWT to verify
/// * `client_id` - The expected Google OAuth client ID (audience)
///
/// # Returns
/// `Ok(GoogleTokenClaims)` if valid, or `AuthError` on failure
pub async fn verify_google_id_token(
    id_token: &str,
    client_id: &str,
) -> Result<GoogleTokenClaims, AuthError> {
    let header = decode_header(id_token)?;
    let kid = header.kid.ok_or(AuthError::InvalidToken)?;

    let jwks = get_google_jwks().await?;
    let jwk = jwks.find(&kid).ok_or(AuthError::InvalidToken)?;

    let decoding_key = DecodingKey::from_jwk(jwk)?;

    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&[client_id]);
    validation.set_issuer(&GOOGLE_ISSUERS);

    let token = decode::<GoogleTokenClaims>(id_token, &decoding_key, &validation).map_err(|e| {
        match e.kind() {
            ErrorKind::ExpiredSignature => return AuthError::Expired,
            ErrorKind::InvalidIssuer => return AuthError::InvalidIssuer,
            ErrorKind::InvalidAudience => return AuthError::InvalidAudience,
            ErrorKind::InvalidToken => return AuthError::InvalidToken,
            ErrorKind::InvalidKeyFormat => return AuthError::KeyFetch,
            _ => return AuthError::Jwt(e),
        }
    })?;

    Ok(token.claims)
}

/// Verifies an Apple ID token and returns its claims if valid.
///
/// # Arguments
/// * `id_token` - The JWT to verify
/// * `client_id` - The expected Apple OAuth client ID (audience)
///
/// # Returns
/// `Ok(AppleTokenClaims)` if valid, or `AuthError` on failure
#[cfg(not(tarpaulin_include))]
pub async fn verify_apple_id_token(
    id_token: &str,
    client_id: &str,
) -> Result<AppleTokenClaims, AuthError> {
    let header = decode_header(id_token)?;
    let kid = header.kid.ok_or(AuthError::InvalidToken)?;

    let jwks = get_apple_jwks().await?;
    let jwk = jwks.find(&kid).ok_or(AuthError::InvalidToken)?;

    let decoding_key = DecodingKey::from_jwk(jwk)?;

    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&[client_id]);
    validation.set_issuer(&APPLE_ISSUERS);

    let token = decode::<AppleTokenClaims>(id_token, &decoding_key, &validation).map_err(|e| {
        match e.kind() {
            ErrorKind::ExpiredSignature => return AuthError::Expired,
            ErrorKind::InvalidIssuer => return AuthError::InvalidIssuer,
            ErrorKind::InvalidAudience => return AuthError::InvalidAudience,
            ErrorKind::InvalidToken => return AuthError::InvalidToken,
            ErrorKind::InvalidKeyFormat => return AuthError::KeyFetch,
            _ => return AuthError::Jwt(e),
        }
    })?;

    Ok(token.claims)
}

#[cfg(not(tarpaulin_include))]
/**
 * Verifies a Cognito ID token and returns its claims if valid.
 *
 * # Arguments
 * * `id_token` - The JWT to verify
 * * `user_pool_id` - The Cognito User Pool ID
 * * `client_id` - The expected Cognito App Client ID (audience)
 * * `region` - The AWS region where the User Pool is located
 *
 * # Returns
 * `Ok(serde_json::Value)` if valid, or `AuthError` on failure
 */
pub async fn verify_cognito_id_token(
    id_token: &str,
    user_pool_id: &str,
    client_id: &str,
    region: &str,
) -> Result<serde_json::Value, AuthError> {
    let issuer_url: String = format!(
        "https://cognito-idp.{}.amazonaws.com/{}",
        region, user_pool_id
    )
    .into();
    let jwks_url: String = format!("{}/.well-known/jwks.json", issuer_url).into();

    let jwks = reqwest::get(jwks_url)
        .await
        .map_err(|_| AuthError::KeyFetch)?
        .json::<JwkSet>()
        .await
        .map_err(|_| AuthError::KeyFetch)?;

    let header = decode_header(id_token)?;
    let kid = header.kid.ok_or(AuthError::InvalidToken)?;

    let jwk = jwks.find(&kid).ok_or(AuthError::InvalidToken)?;
    let decoding_key = DecodingKey::from_jwk(jwk)?;
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&[client_id]);
    validation.set_issuer(&[&issuer_url]);

    let token = decode::<serde_json::Value>(id_token, &decoding_key, &validation).map_err(|e| {
        match e.kind() {
            ErrorKind::ExpiredSignature => return AuthError::Expired,
            ErrorKind::InvalidIssuer => return AuthError::InvalidIssuer,
            ErrorKind::InvalidAudience => return AuthError::InvalidAudience,
            ErrorKind::InvalidToken => return AuthError::InvalidToken,
            ErrorKind::InvalidKeyFormat => return AuthError::KeyFetch,
            _ => return AuthError::Jwt(e),
        }
    })?;

    Ok(token.claims)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_emails() {
        let valid_emails = [
            "email@domain.com",
            "firstname.lastname@domain.com",
            "email@subdomain.domain.com",
            "firstname+lastname@domain.com",
            "1234567890@domain.com",
            "email@domain-one.com",
            "_______@domain.com",
            "email@domain.name",
            "email@domain.co.jp",
            "firstname-lastname@domain.com",
            "very.common@example.com",
            "disposable.style.email.with+symbol@example.com",
            "other.email-with-hyphen@example.com",
            "fully-qualified-domain@example.com",
            "user.name+tag+sorting@example.com",
            "x@example.com",
            "mojojojo@asdf.example.com",
            "example-indeed@strange-example.com",
            "example@s.example",
            "user-@example.org",
            "user@my-example.com",
            "a@b.cd",
            "work+user@mail.com",
            "tom@test.te-st.com",
            "something@subdomain.domain-with-hyphens.tld",
            "francois@etu.inp-n7.fr",
        ];

        for email in valid_emails.iter() {
            assert!(is_valid_email(email), "Expected valid email: {}", email);
        }
    }

    #[test]
    fn test_invalid_emails() {
        let invalid_emails = [
            // no "printable characters"
            r#"user%example.com@example.org"#,
            r#"mailhost!username@example.org"#,
            r#"test/test@test.com"#,
            // Local part starts with dot
            r#".email@domain.com"#,
            // Consecutive dots in local part
            r#"user..name@domain.com"#,
            // double @
            r#"francois@@etu.inp-n7.fr"#,
            // do not support quotes
            r#""email"@domain.com"#,
            r#""e asdf sadf ?<>ail"@domain.com"#,
            r#"" "@example.org"#,
            r#""john..doe"@example.org"#,
            r#""very.(),:;<>[]\".VERY.\"very@\\ \"very\".unusual"@strange.example.com"#,
            // do not support IPv4
            r#"email@123.123.123.123"#,
            r#"email@[123.123.123.123]"#,
            r#"postmaster@123.123.123.123"#,
            r#"user@[68.185.127.196]"#,
            r#"ipv4@[85.129.96.247]"#,
            r#"valid@[79.208.229.53]"#,
            r#"valid@[255.255.255.255]"#,
            r#"valid@[255.0.55.2]"#,
            r#"valid@[255.0.55.2]"#,
            // do not support ipv6
            r#"hgrebert0@[IPv6:4dc8:ac7:ce79:8878:1290:6098:5c50:1f25]"#,
            r#"bshapiro4@[IPv6:3669:c709:e981:4884:59a3:75d1:166b:9ae]"#,
            r#"jsmith@[IPv6:2001:db8::1]"#,
            r#"postmaster@[IPv6:2001:0db8:85a3:0000:0000:8a2e:0370:7334]"#,
            r#"postmaster@[IPv6:2001:0db8:85a3:0000:0000:8a2e:0370:192.168.1.1]"#,
            // microsoft test cases
            r#"plainaddress"#,
            r#"#@%^%#$@#$@#.com"#,
            r#"@domain.com"#,
            r#"Joe Smith &lt;email@domain.com&gt;"#,
            r#"email.domain.com"#,
            r#"email@domain@domain.com"#,
            r#".email@domain.com"#,
            r#"email.@domain.com"#,
            r#"email..email@domain.com"#,
            r#"あいうえお@domain.com"#,
            r#"email@domain.com (Joe Smith)"#,
            r#"email@domain"#,
            r#"email@-domain.com"#,
            r#"email@111.222.333.44444"#,
            r#"email@domain..com"#,
            r#"Abc.example.com"#,
            r#"A@b@c@example.com"#,
            r#"colin..hacks@domain.com"#,
            r#"a"b(c)d,e:f;g<h>i[j\k]l@example.com"#,
            r#"just"not"right@example.com"#,
            r#"this is"not\allowed@example.com"#,
            r#"this\ still\"not\\allowed@example.com"#,
            // random
            r#"i_like_underscore@but_its_not_allowed_in_this_part.example.com"#,
            r#"QA[icon]CHOCOLATE[icon]@test.com"#,
            r#"invalid@-start.com"#,
            r#"invalid@end.com-"#,
            r#"invalid@[1.1.1.-1]"#,
            r#"invalid@[68.185.127.196.55]"#,
            r#"temp@[192.168.1]"#,
            r#"test@.com"#,
        ];

        for email in invalid_emails.iter() {
            assert!(!is_valid_email(email), "Expected invalid email: {}", email);
        }
    }

    #[test]
    fn test_valid_phone_numbers() {
        let valid_numbers = ["+1234567890", "+19876543210", "+447911123456"];

        for number in valid_numbers.iter() {
            assert!(
                is_valid_phone_number(number),
                "Expected valid phone number: {}",
                number
            );
        }
    }

    #[test]
    fn test_invalid_phone_numbers() {
        let invalid_numbers = [
            "1234567890",
            "+12345",
            "hello",
            "+1 (234) 567-8900",
            "00441234567890",
        ];

        for number in invalid_numbers.iter() {
            assert!(
                !is_valid_phone_number(number),
                "Expected invalid phone number: {}",
                number
            );
        }
    }

    #[tokio::test]
    async fn test_verify_google_id_token_invalid() {
        let invalid_token = "invalid.token.here";
        let web_client_id = "your-web-client-id.apps.googleusercontent.com";
        let result = verify_google_id_token(invalid_token, web_client_id).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_verify_google_id_token_expired() {
        // This is a fabricated expired token for testing purposes.
        let expired_token = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjZhOTA2ZWMxMTlkN2JhNDZhNmE0M2VmMWVhODQyZTM0YThlZTA4YjQiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiI0MDc0MDg3MTgxOTIuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiI0MDc0MDg3MTgxOTIuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMDczMjc1Njc4NjIxMDg0Nzg4NDciLCJlbWFpbCI6Im5lcmR5Z2FuZ3N0ZXI0N0BnbWFpbC5jb20iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiYXRfaGFzaCI6IlFXOGZiLTNKU1NsV3Q4NEdONTJVc0EiLCJuYW1lIjoiR2FicmllbCIsInBpY3R1cmUiOiJodHRwczovL2xoMy5nb29nbGV1c2VyY29udGVudC5jb20vYS9BQ2c4b2NKMGUzTkMwcDZrOU5nUzBtZ3h5YzBTbU1yekZnSDcta01aMVhISEZGQ09CTzVzZlN3Nz1zOTYtYyIsImdpdmVuX25hbWUiOiJHYWJyaWVsIiwiaWF0IjoxNzY2MjY3NDAzLCJleHAiOjE3NjYyNzEwMDN9.DQ3KTMJPF_LuhPTctt_JcHfWAvJRWBfAHpvvFpcwmaBMF8THUGiWk4bwwG2E-UhvrrjgngvVUg5Ao5N_UM1QEV3S-soV5vlLeiranpHmuMKAsq4o7q6q5JY81SZzdx7mXqOC5bMutlBNG9dq2bLRUdfVXIuWF6LJeEwymCEkjOIQm0q71s8T0kYGrSAVo4Y5JrnYVdpIJyXgpX0Sg0NXP4IqBS41DJKSP5-ONfZ6YoEWLidcvwl3lb844qQDuGp9vE0FIqNQRimTBhM83MURcRvHK9EKJBQJGj5D9dCTB3H8LLGdf-ytrUVuohxmBey5ftCLe80ntGcllHqQisenJg";
        let web_client_id = "407408718192.apps.googleusercontent.com";
        let result = verify_google_id_token(expired_token, web_client_id).await;
        assert!(result.is_err());
    }
}
