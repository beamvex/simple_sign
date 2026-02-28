#![deny(missing_docs)]

//! Simple signing library
//!
//! This library provides a simple interface for signing and verifying data.

/// RSA cryptographic primitives used by this crate.
pub mod rsa;

/// Secp256k1 (ECDSA) signing primitives used by this crate.
pub mod secp256k1;

/// Ed25519 signing primitives used by this crate.
pub mod ed25519;

/// Signing/verification types and helpers.
pub mod signature;

/// Supported signing algorithms and associated metadata.
pub mod signing_algorithm;

/// Signing interface.
pub mod signer;

/// Signature error types.
pub mod signature_error;

pub use ed25519::Ed25519Signer;
pub use rsa::RsaSigner;
pub use secp256k1::Secp256k1Signer;
pub use signature::Signature;
pub use signature_error::SignatureError;
pub use signer::Signer;
pub use signing_algorithm::SigningAlgorithm;
