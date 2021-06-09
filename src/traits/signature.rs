use crypto_algorithms::HashType;

use crate::{errors::Error, keys::PublicKey};

pub type Signature = Vec<u8>;

pub trait Sign {
    /// The key store type used for `Seal`.
    type KeyStoreType;

    /// The type of the key store id used, i.e. the type for indexing the database.
    type KeyStoreIndex;

    fn sign(
        key_store: &Self::KeyStoreType,
        key_id: &Self::KeyStoreIndex,
        payload: &[u8],
        hash: impl Into<Option<HashType>>,
    ) -> Result<Signature, Error>;
}

pub trait Verify {
    /// The key store type used for `Seal`.
    type KeyStoreType;

    /// The type of the key store id used, i.e. the type for indexing the database.
    type KeyStoreIndex;

    fn verify(
        key_store: &Self::KeyStoreType,
        key_id: &Self::KeyStoreIndex,
        signature: &[u8],
        payload: &[u8],
        hash: impl Into<Option<HashType>>,
    ) -> Result<(), Error>;
    fn verify_with_pk(
        key: &PublicKey,
        signature: &[u8],
        payload: &[u8],
        hash: impl Into<Option<HashType>>,
    ) -> Result<(), Error>;
}
