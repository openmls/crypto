use crypto_algorithms::HashType;

/// Hashing
pub trait Hash {
    /// The return type of [`Hash::hasher()`], a stateful hasher.
    type StatefulHasher;

    /// The error type returned by [`Seal`].
    type Error;

    /// The return type of the [`Hash::hash`] function.
    type Digest;

    /// Single-shot hash
    fn hash(hash: HashType, data: &[u8]) -> Result<Self::Digest, Self::Error>;

    /// Get a stateful hasher object for the streaming API.
    fn hasher(hash: HashType) -> Result<Self::StatefulHasher, Self::Error>
    where
        Self: Sized;
}

/// Streaming API for hashing
pub trait Hasher {
    /// The error type returned by [`Seal`].
    type Error;

    /// The return type of the [`Hasher::finish`] function.
    type Digest;

    /// Add the `data` byte slice to the hash state.
    fn update(&mut self, data: &[u8]) -> Result<(), Self::Error>;

    /// Finish the hash computation and return the result.
    /// This consumes the hasher.
    fn finish(self) -> Result<Self::Digest, Self::Error>;
}
