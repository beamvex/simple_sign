use base_xx::SerialiseError;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[allow(missing_docs)]
pub struct MetaData {
    ord: u8,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
/// Supported signature algorithms.
pub enum SigningAlgorithm {
    /// Ed25519 Edwards-curve signature scheme.
    ED25519,
    /// RSA signature scheme.
    RSA,
    /// ECDSA signature scheme.
    ECDSA,
}

impl SigningAlgorithm {
    #[must_use]
    #[allow(missing_docs)]
    pub const fn metadata(self) -> MetaData {
        match self {
            Self::ED25519 => MetaData { ord: 100 },
            Self::RSA => MetaData { ord: 101 },
            Self::ECDSA => MetaData { ord: 102 },
        }
    }

    #[must_use]
    #[allow(missing_docs)]
    pub const fn ord(self) -> u8 {
        self.metadata().ord
    }
}

impl TryFrom<u8> for SigningAlgorithm {
    type Error = SerialiseError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            100 => Ok(Self::ED25519),
            101 => Ok(Self::RSA),
            102 => Ok(Self::ECDSA),
            _ => Err(SerialiseError::new(format!(
                "Invalid signing algorithm {value}"
            ))),
        }
    }
}

impl From<SigningAlgorithm> for u8 {
    fn from(value: SigningAlgorithm) -> Self {
        match value {
            SigningAlgorithm::ED25519 => 100,
            SigningAlgorithm::RSA => 101,
            SigningAlgorithm::ECDSA => 102,
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_default() {
        let algorithm = SigningAlgorithm::ED25519;
        assert_eq!(algorithm, SigningAlgorithm::ED25519);
    }
}
