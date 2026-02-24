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

/// Signing interface.
pub mod signer;

/// Signature error types.
pub mod signature_error;

pub use signature::Signature;
pub use signature_error::SignatureError;
pub use signer::Signer;
pub use signing_algorithm::SigningAlgorithm;
