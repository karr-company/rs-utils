# rs-utils

![Coverage](assets/coverage.svg)

Reusable Rust helpers for AWS Lambda, DynamoDB, E2E cryptography, validation, and more.

## Modules

| Module | Description | Status |
|--------|-------------|--------|
| [`e2e_crypto`](#e2e_crypto) | Secure E2E encryption (X25519 + AES-256-GCM) | **Recommended** |
| [`json_utils`](#json_utils) | Lambda/API + DynamoDB JSON helpers | Stable |
| [`validation_utils`](#validation_utils) | Email, phone, JWT validation | Stable |
| [`sst_resources`](#sst_resources) | Typed SST resource definitions | Stable |
| [`prompt_utils`](#prompt_utils) | AI prompt safety evaluation | Stable |
| [`vehicle_utils`](#vehicle_utils) | Vehicle data models & rule engine | Stable |

## Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
rs-utils = { git = "..." }
```

Import what you need:

```rust
use rs_utils::{
    encrypt_for_recipient, decrypt_message, HkdfParams,
    is_valid_email, json_response, Table,
};
```

---

## e2e_crypto

NIST-compliant end-to-end encryption using X25519 ECDH + HKDF-SHA256 + AES-256-GCM. Cross-platform compatible with Node.js `crypto` module.

### Key generation

```rust
use rs_utils::e2e_crypto::generate_keypair;

let keys = generate_keypair();
// keys.public_key  -> String (base64)
// keys.private_key -> String (base64, store securely)
```

### Encrypt / decrypt

```rust
use rs_utils::e2e_crypto::{encrypt_for_recipient, decrypt_message, HkdfParams};

let server_keys = generate_keypair();
let params = HkdfParams::new("e2e-v1-salt", "e2e-v1-aes-gcm-key");

let encrypted = encrypt_for_recipient("Hello server!", &server_keys.public_key, &params)?;
let plaintext = decrypt_message(&encrypted, &server_keys.private_key, &params)?;
assert_eq!(plaintext, "Hello server!");
```

### API keys

```rust
use rs_utils::e2e_crypto::{generate_api_key, verify_api_key_secret};

let pepper = "secret-pepper-from-env";
let bundle = generate_api_key(pepper);

// Store bundle.key_id + bundle.hashed_secret in DB
// Give bundle.full_key to the client

let is_valid = verify_api_key_secret(&bundle.secret, pepper, &bundle.hashed_secret);
```

### Key types

- `E2eKeyPair` — public/private key pair (base64-encoded)
- `E2eEncryptedMessage` — ciphertext + nonce + ephemeral public key
- `HkdfParams` — salt and info strings for key derivation
- `ApiKeyBundle` — generated API key with `key_id`, `hashed_secret`, `secret`, `full_key`

---

## json_utils

Helpers for Lambda HTTP responses and DynamoDB type conversions.

### Responses

```rust
use rs_utils::{json_response, empty_json_response, error_response};

// 200 JSON
let resp = json_response(r#"{"ok":true}"#.into())?;

// 200 empty
let resp = empty_json_response()?;

// Error with status code
let resp = error_response(400, "Bad request".into())?;
```

### DynamoDB conversion

```rust
use rs_utils::{attribute_value_to_json, item_to_json_map, convert_and_deserialize};

let json: serde_json::Value = attribute_value_to_json(&dynamodb_attr);
let map = item_to_json_map(&dynamodb_item);
let my_struct: MyType = convert_and_deserialize(&dynamodb_item)?;
```

### UploadWithFields

```rust
use rs_utils::UploadWithFields;

let upload = UploadWithFields::from(presigned_post);
// upload.url, upload.fields
```

---

## validation_utils

### Email & phone

```rust
use rs_utils::{is_valid_email, is_valid_phone_number};

assert!(is_valid_email("user@example.com"));
assert!(is_valid_phone_number("+447700900000"));
```

### JWT verification

Supports Google, Apple, and AWS Cognito ID token verification with JWKS caching.

```rust
use rs_utils::{
    verify_google_id_token, verify_apple_id_token, verify_cognito_id_token,
    GoogleTokenClaims, AppleTokenClaims, AuthError,
};

let claims: GoogleTokenClaims = verify_google_id_token(
    token, "client-id", "issuer",
)?;
```

---

## sst_resources

Strongly-typed SST resource references for infrastructure-as-code.

| Struct | Field | Description |
|--------|-------|-------------|
| `Table` | `name` | DynamoDB table |
| `Bucket` | `name` | S3 bucket |
| `Secret` | `value` | Secret value |
| `Queue` | `url` | SQS queue URL |
| `UserPool` | `id` | Cognito user pool |
| `UserPoolClient` | `id` | Cognito user pool client |
| `IdentityPool` | `id` | Cognito identity pool |
| `Email` | `sender` | SES email sender |
| `Topic` | `arn` | SNS topic ARN |
| `StepFunction` | `arn` | Step Function ARN |
| `Function` | `name` | Lambda function name |

All types derive `Serialize` and `Deserialize`.

---

## prompt_utils

Safe prompt evaluation using tokenization, stopword filtering, and weighted scoring.

```rust
use rs_utils::safe_prompt;

let result = safe_prompt("What is the capital of France?".into(), 50);
assert!(result.is_ok());
```

Tokens are classified as `Critical` or `Soft`. The safety score is a weighted combination (70% critical, 30% soft). Prompts exceeding the threshold are rejected.

---

## vehicle_utils

Data models and a rules engine for vehicle enforcement (PCNs, fines, tax status).

```rust
use rs_utils::{Vehicle, ScannedVehicleFine, RuleEngine, Rule, Condition, ResultValue};

let engine: RuleEngine = serde_json::from_str(r#"{
    "roadId": "M1",
    "resultType": "BOOLEAN",
    "rules": [...],
    "default": false
}"#)?;

let result = engine.evaluate(&vehicle, scanned_fine);
```

Supports compound conditions (`Any`, `All`, `Not`, `Always`) and typed predicates on vehicle fields (wheelplan, fuel type, Euro status, engine capacity, etc.).

---

## Binary: `generate_keypair`

A CLI tool that generates an X25519 key pair and prints it as JSON.

```bash
cargo run --bin generate_keypair
```

Output:

```json
{
  "publicKey": "...",
  "privateKey": "..."
}
```

---

## Migration from `crypto_box` to `e2e_crypto`

- NIST-compliant (AES-256-GCM vs. NaCl)
- Forward secrecy via ephemeral keys per message
- Cross-platform (Node.js, React Native via Web Crypto API)

## Notes

- `cockroach_utils` is internal/legacy and not exported from the crate root.
- `stoplist` and `token_map` are internal modules for `prompt_utils`.
