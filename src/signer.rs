use crate::{Signature, SignatureError};

/// Trait for signing data.
///
/// This trait defines the interface for signing data with a specific algorithm.
pub trait Signer {
    /// Sign the given data.
    ///
    /// # Errors
    ///
    /// Returns an error if the signing operation fails.
    fn sign(&self, data: &[u8]) -> Result<Signature, SignatureError>;
}
