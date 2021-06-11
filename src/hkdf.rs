use crypto_algorithms::HashType;
use key_store::types::Status;

/// HKDF
pub trait HkdfDerive {
    /// The key store type used for `Seal`.
    type KeyStoreType;

    /// The type of the key store id used, i.e. the type for indexing the database.
    type KeyStoreIndex;

    /// The type of the secrets used in HKDF.
    type Secret;

    /// The error type returned by [`HkdfDerive`].
    type Error;

    /// HKDF
    /// Compute HKDF on the input and store it with the `okm` id.
    fn hkdf(
        key_store: &Self::KeyStoreType,
        ikm: &Self::KeyStoreIndex,
        hash: HashType,
        salt: &[u8],
        info: &[u8],
        out_len: usize,
        okm: &Self::KeyStoreIndex,
    ) -> Result<(), Self::Error>;

    /// HKDF extract
    /// Extract pre-key material from `ikm` and store it with the `prk` id.
    fn extract(
        key_store: &Self::KeyStoreType,
        ikm: &Self::KeyStoreIndex,
        hash: HashType,
        salt: &[u8],
        okm: &Self::KeyStoreIndex,
    ) -> Result<(), Self::Error>;

    /// HKDF expand
    /// The expanded secret is stored with the `okm` id.
    fn expand(
        key_store: &Self::KeyStoreType,
        prk: &Self::KeyStoreIndex,
        hash: HashType,
        info: &[u8],
        out_len: usize,
        okm: &Self::KeyStoreIndex,
    ) -> Result<(), Self::Error>;

    /// HKDF
    /// Compute HKDF on the input and store it with the `okm` id.
    fn hkdf_with_status(
        key_store: &Self::KeyStoreType,
        ikm: &Self::KeyStoreIndex,
        hash: HashType,
        salt: &[u8],
        info: &[u8],
        out_len: usize,
        okm: &Self::KeyStoreIndex,
        status: Status,
    ) -> Result<(), Self::Error>;

    /// HKDF extract
    /// Extract pre-key material from `ikm` and store it with the `prk` id with
    /// the provided `status`.
    fn extract_with_status(
        key_store: &Self::KeyStoreType,
        ikm: &Self::KeyStoreIndex,
        hash: HashType,
        salt: &[u8],
        okm: &Self::KeyStoreIndex,
        status: Status,
    ) -> Result<(), Self::Error>;

    /// HKDF expand
    /// The expanded secret is stored with the `okm` id with the provided `status`.
    fn expand_with_status(
        key_store: &Self::KeyStoreType,
        prk: &Self::KeyStoreIndex,
        hash: HashType,
        info: &[u8],
        out_len: usize,
        okm: &Self::KeyStoreIndex,
        status: Status,
    ) -> Result<(), Self::Error>;
}
