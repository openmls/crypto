use crypto_algorithms::HashType;

use crate::{errors::Error, secret::Secret};

/// HKDF
pub trait HkdfDerive {
    /// The key store type used for `Seal`.
    type KeyStoreType;

    /// The type of the key store id used, i.e. the type for indexing the database.
    type KeyStoreIndex;

    /// HKDF extract
    /// Panics if not implemented.
    /// This can also be used to compute an HMAC.
    /// ☣️ **NOTE** that this returns secret key material.
    fn extract(
        _key_store: &Self::KeyStoreType,
        _ikm: &Self::KeyStoreIndex,
        _hash: HashType,
        _salt: &[u8],
    ) -> Result<Secret, Error> {
        unimplemented!();
    }

    /// HKDF expand
    /// Panics if not implemented.
    /// ☣️ **NOTE** that this returns secret key material.
    fn expand(
        _key_store: &Self::KeyStoreType,
        _prk: &Self::KeyStoreIndex,
        _hash: HashType,
        _info: &[u8],
        _out_len: usize,
    ) -> Result<Secret, Error> {
        unimplemented!();
    }

    /// HKDF
    /// Compute HKDF on the input and store it with the `okm` id.
    /// This is the only function that must be implemented.
    fn hkdf(
        key_store: &Self::KeyStoreType,
        ikm: &Self::KeyStoreIndex,
        hash: HashType,
        salt: &[u8],
        info: &[u8],
        out_len: usize,
        okm: &Self::KeyStoreIndex,
    ) -> Result<(), Error>;

    /// HKDF
    /// Panics if not implemented.
    /// ☣️ **NOTE** that this returns secret key material.
    fn hkdf_export(
        _key_store: &Self::KeyStoreType,
        _ikm: &Self::KeyStoreIndex,
        _hash: HashType,
        _salt: &[u8],
        _info: &[u8],
        _out_len: usize,
    ) -> Result<Secret, Error> {
        unimplemented!();
    }
}
