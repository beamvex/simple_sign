use ed25519_dalek::Signer as _;
use rand_core::OsRng;
use slahasher::Hash;

use crate::Signature;
use crate::SignatureError;
use crate::Signer;
use crate::SigningAlgorithm;

/// An Ed25519 signer.
pub struct Ed25519Signer {
    signing_key: ed25519_dalek::SigningKey,
}

impl Ed25519Signer {
    /// Creates a new `Ed25519Signer` from an existing Ed25519 signing key.
    #[must_use]
    pub const fn new(signing_key: ed25519_dalek::SigningKey) -> Self {
        Self { signing_key }
    }

    /// Generates a new random Ed25519 signing key and returns a signer.
    #[must_use]
    pub fn new_random() -> Self {
        Self {
            signing_key: ed25519_dalek::SigningKey::generate(&mut OsRng),
        }
    }

    /// Returns a reference to the signing key held by this signer.
    #[must_use]
    pub const fn get_signing_key(&self) -> &ed25519_dalek::SigningKey {
        &self.signing_key
    }

    /// Returns the corresponding verifying key.
    #[must_use]
    pub fn get_verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.signing_key.verifying_key()
    }
}

impl Default for Ed25519Signer {
    /// Creates a default `Ed25519Signer`.
    fn default() -> Self {
        Self::new_random()
    }
}

impl Signer for Ed25519Signer {
    /// Signs the provided hash and returns the resulting signature.
    fn sign(&self, hash: &Hash) -> Result<Signature, SignatureError> {
        let signature: ed25519_dalek::Signature = self.signing_key.sign(hash.get_bytes());
        Ok(Signature::new_with_algorithm(
            SigningAlgorithm::ED25519,
            signature.to_bytes().to_vec(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base_xx::{ByteVec, EncodedString, Encoding, byte_vec::Encodable};
    use slahasher::HashAlgorithm;
    use slogger::debug;

    #[test]
    fn test_ed25519_sign() {
        let signer = Ed25519Signer::default();
        let data = b"test";
        let bytes = ByteVec::new(data.to_vec());
        let hash =
            Hash::try_hash(&bytes, HashAlgorithm::KECCAK512).unwrap_or_else(|_| unreachable!());

        let signature = signer.sign(&hash).unwrap_or_else(|_| unreachable!());
        let serialised = signature
            .try_encode(Encoding::Base58)
            .unwrap_or_else(|_| EncodedString::new(Encoding::Base58, String::new()));
        debug!("signature {serialised}");
        assert_eq!(signature.get_algorithm(), SigningAlgorithm::ED25519);
        assert_eq!(signature.get_signature().len(), 64);
    }
}
