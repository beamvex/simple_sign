use base_xx::{ByteVec, byte_vec::Encodable};
use rand_core::OsRng;

use crate::Signature;
use crate::SignatureError;
use crate::Signer;

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
    /// Signs `data` and returns the resulting signature.
    fn sign(&self, _data: &[u8]) -> Result<Signature, SignatureError> {
        unimplemented!()
    }
}

/// A test struct for serialisation.
pub struct Test {
    data: Vec<u8>,
}

impl Test {
    /// Creates a new Test instance from raw data.
    #[must_use]
    pub const fn new(data: Vec<u8>) -> Self {
        Self { data }
    }
}

impl TryFrom<ByteVec> for Test {
    type Error = base_xx::SerialiseError;

    fn try_from(value: ByteVec) -> Result<Self, Self::Error> {
        Ok(Self {
            data: value.get_bytes().to_vec(),
        })
    }
}

impl TryFrom<&Test> for ByteVec {
    type Error = base_xx::SerialiseError;

    fn try_from(value: &Test) -> Result<Self, Self::Error> {
        Ok(Self::new(value.data.clone()))
    }
}

impl Encodable for Test {}

#[cfg(test)]
mod tests {

    use super::*;
    use base_xx::Encoding;
    use rand::rngs::OsRng;
    use rsa::RsaPrivateKey;
    use rsa::pkcs1::EncodeRsaPrivateKey;
    use rsa::pkcs1v15::Pkcs1v15Sign;
    use rsa::pkcs8::LineEnding;
    use rsa::traits::PublicKeyParts;
    use sha2::{Digest, Sha256};

    use slogger::debug;

    #[test]
    fn test_rsa() {
        let mut rng = OsRng;
        match RsaPrivateKey::new(&mut rng, 256) {
            Ok(private_key) => {
                assert_eq!(private_key.n().bits(), 256);

                match private_key.to_pkcs1_pem(LineEnding::LF) {
                    Ok(pem) => {
                        let pem = pem.as_str();
                        debug!("pem {pem}");
                    }
                    Err(e) => {
                        debug!("failed to generate RSA key: {e}");
                    }
                }

                let _n = private_key.n();
                let _e = private_key.e();

                let test = b"test";
                let digest = Sha256::digest(test);
                let signresult =
                    private_key.sign(Pkcs1v15Sign::new_unprefixed(), digest.as_slice());

                match signresult {
                    Ok(signature) => {
                        let bytes = Test::new(signature);
                        match bytes.try_encode(Encoding::Base36) {
                            Ok(encoded) => {
                                debug!("signature {encoded}");
                            }
                            Err(e) => {
                                debug!("failed to encode signature: {e}");
                            }
                        }
                    }
                    Err(e) => {
                        debug!("signing failed: {e}");
                    }
                }

                let public_key = private_key.to_public_key();
                let n = public_key.n().to_bytes_be();
                let bytes = Test::new(n);
                match bytes.try_encode(Encoding::Base36) {
                    Ok(encoded) => {
                        debug!("n {encoded}");
                    }
                    Err(e) => {
                        debug!("failed to encode n: {e}");
                    }
                }
            }
            Err(e) => {
                debug!("failed to generate RSA key: {e}");
            }
        }
    }
}
