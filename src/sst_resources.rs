//! SST Resource Type Definitions
//!
//! This module provides strongly-typed representations of SST (Serverless Stack Toolkit) resources
//! such as DynamoDB tables, S3 buckets, secrets, and SQS queues. These types are used for
//! configuration and resource referencing in infrastructure-as-code and Lambda integrations.
//!
//! All types are serializable and deserializable via Serde.
use serde::{Deserialize, Serialize};

// SST DynamoDB Table Resource
#[cfg(not(tarpaulin_include))]
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct Table {
    pub name: String,
}

/// SST S3 Bucket Resource
#[cfg(not(tarpaulin_include))]
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct Bucket {
    pub name: String,
}

/// SST Secret Resource
#[cfg(not(tarpaulin_include))]
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct Secret {
    pub value: String,
}

/// SST SQS Queue Resource
#[cfg(not(tarpaulin_include))]
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct Queue {
    pub url: String,
}

/// SST User Pool Resource
#[cfg(not(tarpaulin_include))]
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct UserPool {
    pub id: String,
}

/// SST User Pool Client Resource
#[cfg(not(tarpaulin_include))]
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct UserPoolClient {
    pub id: String,
}

/// SST Identity Pool Resource
#[cfg(not(tarpaulin_include))]
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct IdentityPool {
    pub id: String,
}

/// SST Email Resource
#[cfg(not(tarpaulin_include))]
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct Email {
    pub sender: String,
}

/// SST SNS Topic Resource
#[cfg(not(tarpaulin_include))]
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct Topic {
    pub arn: String,
}