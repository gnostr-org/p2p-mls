use openmls::prelude::{ProcessMessageError, WelcomeError};
use openmls_rust_crypto::MemoryStorageError;
use std::fmt::Display;

#[derive(Debug)]
pub struct NodeError(pub String);

impl std::error::Error for NodeError {}

impl Display for NodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<WelcomeError<MemoryStorageError>> for NodeError {
    fn from(error: WelcomeError<MemoryStorageError>) -> Self {
        NodeError(error.to_string())
    }
}

impl From<ProcessMessageError<MemoryStorageError>> for NodeError {
    fn from(error: ProcessMessageError<MemoryStorageError>) -> Self {
        NodeError(error.to_string())
    }
}
