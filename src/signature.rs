use crypto_algorithms::HashType;

pub trait Sign {
    /// The key store type used for [`Sign`].
    type KeyStoreType;

    /// The type of the key store id used, i.e. the type for indexing the database.
    type KeyStoreIndex;

    /// The type of the signature produced by [`Sign::sign()`].
    type Signature;

    /// The error type returned by [`Sign`].
    type Error;

    fn sign(
        key_store: &Self::KeyStoreType,
        key_id: &Self::KeyStoreIndex,
        payload: &[u8],
        hash: impl Into<Option<HashType>>,
    ) -> Result<Self::Signature, Self::Error>;
}

pub trait Verify {
    /// The key store type used for [`Sign`].
    type KeyStoreType;

    /// The type of the key store id used, i.e. the type for indexing the database.
    type KeyStoreIndex;

    /// The type of the public key used to verify the signature.
    type PublicKey;

    /// The error type returned by [`Sign`].
    type Error;

    fn verify(
        key_store: &Self::KeyStoreType,
        key_id: &Self::KeyStoreIndex,
        signature: &[u8],
        payload: &[u8],
        hash: impl Into<Option<HashType>>,
    ) -> Result<(), Self::Error>;

    fn verify_with_pk(
        key: &Self::PublicKey,
        signature: &[u8],
        payload: &[u8],
        hash: impl Into<Option<HashType>>,
    ) -> Result<(), Self::Error>;
}
