//! JSON Utilities for Lambda / API Responses and DynamoDB Conversions
//!
//! This module provides:
//! - Standardized JSON response helpers for API / Lambda functions
//! - Conversion of AWS DynamoDB `AttributeValue` to `serde_json::Value`
//! - Utility to convert DynamoDB items to Rust structs via `serde_json`

use anyhow::Result;
use aws_sdk_dynamodb::types::AttributeValue;
use lambda_http::{Body, Error as LambdaError, Response, http::StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashMap;

/// Generates a JSON HTTP response with the given payload
///
/// # Arguments
/// * `payload` - JSON string to include in the response body
///
/// # Returns
/// `Response<Body>` with status 200 and content-type application/json
pub fn json_response(payload: String) -> Result<Response<Body>, LambdaError> {
    let rsp = Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(payload.into())
        .map_err(Box::new)?;
    Ok(rsp)
}

/// Generates an empty JSON response (`{}`)
///
/// # Returns
/// `Response<Body>` with status 200 and content-type application/json
pub fn empty_json_response() -> Result<Response<Body>, LambdaError> {
    let rsp = Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(json!({}).to_string().into())
        .map_err(Box::new)?;
    Ok(rsp)
}

/// Generates an error JSON response with a custom message and status code
///
/// # Arguments
/// * `err` - `std::error::Error` containing error details
/// * `status_code` - `StatusCode` for the HTTP response
///
/// # Returns
/// `Response<Body>` with error message in JSON
pub fn error_response(
    err: &dyn std::error::Error,
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

/// Converts a DynamoDB `AttributeValue` into `serde_json::Value`
///
/// Handles strings, numbers, maps, lists, booleans, nulls, and nested structures
pub fn attribute_value_to_json(av: &AttributeValue) -> Value {
    if let Ok(s) = av.as_s() {
        Value::String(s.to_string())
    } else if let Ok(n) = av.as_n() {
        if let Ok(int_val) = n.parse::<i64>() {
            Value::Number(int_val.into())
        } else if let Ok(float_val) = n.parse::<f64>() {
            Value::Number(serde_json::Number::from_f64(float_val).unwrap())
        } else {
            Value::String(n.to_string())
        }
    } else if let Ok(m) = av.as_m() {
        let map_json: serde_json::Map<String, Value> = m
            .iter()
            .map(|(k, v)| (k.clone(), attribute_value_to_json(v)))
            .collect();
        Value::Object(map_json)
    } else if let Ok(l) = av.as_l() {
        let list_json: Vec<Value> = l.iter().map(attribute_value_to_json).collect();
        Value::Array(list_json)
    } else if let Ok(b) = av.as_bool() {
        Value::Bool(*b)
    } else if av.is_null() {
        Value::Null
    } else {
        Value::Null
    }
}

/// Converts a DynamoDB item (HashMap) into a JSON Map
///
/// # Arguments
/// * `item` - DynamoDB item: `HashMap<String, AttributeValue>`
///
/// # Returns
/// `serde_json::Map<String, Value>` representing the item
pub fn item_to_json_map(item: &HashMap<String, AttributeValue>) -> serde_json::Map<String, Value> {
    item.iter()
        .map(|(k, v)| (k.clone(), attribute_value_to_json(v)))
        .collect()
}

/// Converts a DynamoDB item into a Rust struct using serde deserialization
///
/// # Arguments
/// * `item` - DynamoDB item: `HashMap<String, AttributeValue>`
///
/// # Returns
/// `Result<T, serde_json::Error>` where `T` is a serde-deserializable struct
pub fn convert_and_deserialize<T: serde::de::DeserializeOwned>(
    item: HashMap<String, AttributeValue>,
) -> Result<T, serde_json::Error> {
    let json_map = item_to_json_map(&item);
    let json_value = Value::Object(json_map);
    serde_json::from_value(json_value)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DynamicItem {
    #[serde(flatten)]
    fields: HashMap<String, Value>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::anyhow;
    use aws_sdk_dynamodb::types::AttributeValue;
    use lambda_http::http::StatusCode;
    use serde_json::Value;
    use std::collections::HashMap;

    #[tokio::test]
    async fn test_json_response() {
        let payload = "{\"key\":\"value\"}".to_string();
        let response = json_response(payload).unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_error_response() {
        let err = anyhow!("Test error");
        let std_err: &dyn std::error::Error = err.as_ref();
        let response = error_response(std_err, StatusCode::BAD_REQUEST).unwrap();
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
        assert_eq!(
            attribute_value_to_json(&av_string),
            Value::String("test".to_string())
        );

        let av_number = AttributeValue::N("42".to_string());
        assert_eq!(
            attribute_value_to_json(&av_number),
            Value::Number(42.into())
        );

        let mut map = HashMap::new();
        map.insert("key".to_string(), AttributeValue::S("value".to_string()));
        let av_map = AttributeValue::M(map.clone());
        let mut expected_map = serde_json::Map::new();
        expected_map.insert("key".to_string(), Value::String("value".to_string()));
        assert_eq!(
            attribute_value_to_json(&av_map),
            Value::Object(expected_map)
        );
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
        #[derive(serde::Deserialize)]
        struct TestItem {
            field1: String,
            field2: i64,
        }

        let mut item = HashMap::new();
        item.insert(
            "field1".to_string(),
            AttributeValue::S("value1".to_string()),
        );
        item.insert("field2".to_string(), AttributeValue::N("42".to_string()));

        let result: TestItem = convert_and_deserialize(item).unwrap();
        assert_eq!(result.field1, "value1");
        assert_eq!(result.field2, 42);
    }
}
