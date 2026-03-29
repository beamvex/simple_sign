use std::sync::Arc;

use base_xx::ByteVec;
use rand_core::OsRng;
use rsa::Pkcs1v15Sign;
use slahasher::Hash;

use crate::Signature;
use crate::SignatureError;
use crate::Signer;
use crate::SigningAlgorithm;

/// An RSA signer.
pub struct RsaSigner {
    private_key: rsa::RsaPrivateKey,
}

impl RsaSigner {
    /// Creates a new `RsaSigner` from an existing RSA private key.
    #[must_use]
    pub const fn new(private_key: rsa::RsaPrivateKey) -> Self {
        Self { private_key }
    }

    /// Returns a reference to the RSA private key held by this signer.
    #[must_use]
    pub const fn get_private_key(&self) -> &rsa::RsaPrivateKey {
        &self.private_key
    }

    /// Returns the corresponding RSA public key.
    #[must_use]
    pub fn get_public_key(&self) -> rsa::RsaPublicKey {
        self.private_key.to_public_key()
    }

    /// Generates a new RSA private key with the given size (in bits) and returns a signer.
    pub fn new_with_size(bit_size: usize) -> Self {
        Self {
            private_key: rsa::RsaPrivateKey::new(&mut OsRng, bit_size)
                .unwrap_or_else(|_| unreachable!()),
        }
    }
}

impl Default for RsaSigner {
    /// Creates a default `RsaSigner`.
    ///
    /// Currently this generates a new RSA key with a default size.
    fn default() -> Self {
        Self::new_with_size(256)
    }
}

impl Signer for RsaSigner {
    /// Signs the provided hash and returns the resulting signature.
    fn sign(self: Arc<Self>, hash: Arc<Hash>) -> Result<Arc<Signature>, SignatureError> {
        let signresult = self
            .private_key
            .sign(Pkcs1v15Sign::new_unprefixed(), hash.get_bytes().get_bytes());

        match signresult {
            Ok(signature) => Ok(Arc::new(Signature::new_with_algorithm(
                SigningAlgorithm::RSA,
                Arc::new(ByteVec::new(Arc::new(signature))),
            ))),
            Err(e) => Err(SignatureError::new(e.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    use base_xx::{ByteVec, EncodedString, Encoding, byte_vec::Encodable};
    use slahasher::HashAlgorithm;
    use slogger::debug;

    #[test]
    fn test_rsa() {
        let signer = RsaSigner::new_with_size(1024);

        let data = b"test";
        let bytes = Arc::new(ByteVec::new(Arc::new(data.to_vec())));
        let hash = Hash::try_hash(Arc::clone(&bytes), HashAlgorithm::KECCAK512)
            .unwrap_or_else(|_| unreachable!());

        let signature = RsaSigner::sign(Arc::new(signer), hash).unwrap_or_else(|_| unreachable!());
        let serialised = Arc::clone(&signature)
            .try_encode(Encoding::Base58)
            .unwrap_or_else(|_| EncodedString::new(Encoding::Base58, String::new()));
        debug!("signature {serialised}");
        assert_eq!(signature.get_algorithm(), SigningAlgorithm::RSA);
        assert_eq!(signature.get_signature().get_bytes().len(), 128);
    }
}
