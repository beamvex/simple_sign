use k256::ecdsa;
use k256::ecdsa::signature::Signer as _;
use rand_core::OsRng;
use slahasher::Hash;

use crate::Signature;
use crate::SignatureError;
use crate::Signer;
use crate::SigningAlgorithm;

/// A Secp256k1 (ECDSA) signer.
pub struct Secp256k1Signer {
    signing_key: ecdsa::SigningKey,
}

impl Secp256k1Signer {
    /// Creates a new `Secp256k1Signer` from an existing signing key.
    #[must_use]
    pub const fn new(signing_key: ecdsa::SigningKey) -> Self {
        Self { signing_key }
    }

    /// Generates a new random Secp256k1 signing key and returns a signer.
    #[must_use]
    pub fn new_random() -> Self {
        Self {
            signing_key: ecdsa::SigningKey::random(&mut OsRng),
        }
    }

    /// Returns a reference to the signing key held by this signer.
    #[must_use]
    pub const fn get_signing_key(&self) -> &ecdsa::SigningKey {
        &self.signing_key
    }

    /// Returns the corresponding verifying key.
    #[must_use]
    pub fn get_verifying_key(&self) -> ecdsa::VerifyingKey {
        *self.signing_key.verifying_key()
    }
}

impl Default for Secp256k1Signer {
    /// Creates a default `Secp256k1Signer`.
    fn default() -> Self {
        Self::new_random()
    }
}

impl Signer for Secp256k1Signer {
    /// Signs the provided hash and returns the resulting signature.
    fn sign(&self, hash: &Hash) -> Result<Signature, SignatureError> {
        let signature: ecdsa::Signature = self.signing_key.sign(hash.get_bytes());
        Ok(Signature::new_with_algorithm(
            SigningAlgorithm::ECDSA,
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
    fn test_secp256k1_sign() {
        let signer = Secp256k1Signer::default();
        let data = b"test";
        let bytes = ByteVec::new(data.to_vec());
        let hash =
            Hash::try_hash(&bytes, HashAlgorithm::KECCAK512).unwrap_or_else(|_| unreachable!());

        let signature = signer.sign(&hash).unwrap_or_else(|_| unreachable!());
        let serialised = signature
            .try_encode(Encoding::Base58)
            .unwrap_or_else(|_| EncodedString::new(Encoding::Base58, String::new()));
        debug!("signature {serialised}");
        assert_eq!(signature.get_algorithm(), SigningAlgorithm::ECDSA);
        assert_eq!(signature.get_signature().len(), 64);
    }
}
