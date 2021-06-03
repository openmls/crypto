use crypto_algorithms::AeadType;

use crate::errors::Error;

pub type Tag = Vec<u8>;
pub type Ciphertext = Vec<u8>;
pub type CiphertextTag = (Ciphertext, Tag);
pub type Plaintext = Vec<u8>;

/// AEAD
pub trait Seal {
    /// The key store type used for `Seal`.
    type KeyStoreType;

    /// The type of the key store id used, i.e. the type for indexing the database.
    type KeyStoreIndex;

    /// Encrypt the `msg` with the given parameters and return the cipher text
    /// and tag values as byte vectors in `Ciphertext`.
    fn seal(
        key_store: &Self::KeyStoreType,
        key_id: &Self::KeyStoreIndex,
        aead: AeadType,
        msg: &[u8],
        aad: &[u8],
        nonce: &[u8],
    ) -> Result<CiphertextTag, Error>;

    /// Encrypt the `msg` with the given parameters and return the cipher text
    /// and tag concatenated in a byte vector.
    fn seal_combined(
        key_store: &Self::KeyStoreType,
        key_id: &Self::KeyStoreIndex,
        aead: AeadType,
        msg: &[u8],
        aad: &[u8],
        nonce: &[u8],
    ) -> Result<Vec<u8>, Error>;

    /// Encrypt the `msg` with the given parameters and return the cipher text
    /// in place of the msg and the tag as byte vector.
    fn seal_in_place(
        key_store: &Self::KeyStoreType,
        key_id: &Self::KeyStoreIndex,
        aead: AeadType,
        msg: &mut [u8],
        aad: &[u8],
        nonce: &[u8],
    ) -> Result<Vec<u8>, Error>;

    /// Encrypt the `msg` with the given parameters and return the cipher text
    /// in place of the msg.
    /// *NOTE* that this requires the msg slice to be of length input msg + tag length.
    fn seal_in_place_combined(
        key_store: &Self::KeyStoreType,
        key_id: &Self::KeyStoreIndex,
        aead: AeadType,
        msg: &mut [u8],
        aad: &[u8],
        nonce: &[u8],
    ) -> Result<(), Error>;
}
pub trait Open {
    /// The key store type used for `Open`.
    type KeyStoreType;

    /// The type of the key store id used, i.e. the type for indexing the database.
    type KeyStoreIndex;

    /// Decrypt the `cipher_text` with the given parameters and return the plain
    /// text as byte vector.
    fn open(
        key_store: &Self::KeyStoreType,
        key_id: &Self::KeyStoreIndex,
        aead: AeadType,
        cipher_text: &CiphertextTag,
        aad: &[u8],
        nonce: &[u8],
    ) -> Result<Plaintext, Error>;

    /// Decrypt the `cipher_text`, which is the concatenated cipher text and tag,
    /// with the given parameters and return the plain text as byte vector.
    fn open_combined(
        key_store: &Self::KeyStoreType,
        key_id: &Self::KeyStoreIndex,
        aead: AeadType,
        cipher_text: &[u8],
        aad: &[u8],
        nonce: &[u8],
    ) -> Result<Plaintext, Error>;
}
