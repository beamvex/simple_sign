/// Error type for signature operations.
#[derive(Debug)]
pub struct SignatureError {
    message: String,
}

impl SignatureError {
    /// Create a new signature error.
    ///
    /// # Arguments
    ///
    /// * `message` - The error message.
    ///
    /// # Returns
    ///
    /// A new `SignatureError`.
    #[must_use]
    pub const fn new(message: String) -> Self {
        Self { message }
    }

    /// Get the error message.
    ///
    /// # Returns
    ///
    /// The error message.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}
