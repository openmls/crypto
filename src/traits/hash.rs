use crypto_algorithms::HashType;

use crate::errors::Error;

/// Hashing
pub trait Hash {
    type StatefulHasher;

    /// Single-shot hash
    fn hash(hash: HashType, data: &[u8]) -> Result<Vec<u8>, Error>;

    /// Get a stateful hasher object for the streaming API.
    fn hasher(hash: HashType) -> Result<Self::StatefulHasher, Error>
    where
        Self: Sized;
}

/// Streaming API for hashing
pub trait Hasher {
    fn update(&mut self, data: &[u8]) -> Result<(), Error>;
    fn finish(&mut self) -> Result<Vec<u8>, Error>;
}
