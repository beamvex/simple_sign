#![deny(missing_docs)]

//! Simple signing library
//!
//! This library provides a simple interface for signing and verifying data.

/// RSA cryptographic primitives used by this crate.
pub mod rsa;

/// Signing/verification types and helpers.
pub mod signature;

/// Supported signing algorithms and associated metadata.
pub mod signing_algorithm;

pub use signature::Signature;
pub use signing_algorithm::SigningAlgorithm;
