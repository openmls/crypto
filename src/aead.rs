use crypto_algorithms::AeadType;

/// AEAD Seal
pub trait Seal {
    /// The key store type used for `Seal`.
    type KeyStoreType;

    /// The type of the key store id used, i.e. the type for indexing the database.
    type KeyStoreIndex;

    /// The error type returned by [`Seal`].
    type Error;

    /// The ciphertext and tag return type of [`Seal::seal()`].
    type CiphertextTag;

    /// The tag return type of [`Seal::seal_in_place()`].
    type Tag;

    /// Encrypt the `msg` with the given parameters and return the cipher text
    /// and tag values as byte vectors in `Ciphertext`.
    fn seal(
        key_store: &Self::KeyStoreType,
        key_id: &Self::KeyStoreIndex,
        aead: AeadType,
        msg: &[u8],
        aad: &[u8],
        nonce: &[u8],
    ) -> Result<Self::CiphertextTag, Self::Error>;

    /// Encrypt the `msg` with the given parameters and return the cipher text
    /// in place of the msg and the tag as byte vector.
    ///
    /// [`Self::Tag`] can be `()`.
    /// This requires the msg slice to be of length input msg + tag length.
    fn seal_in_place(
        key_store: &Self::KeyStoreType,
        key_id: &Self::KeyStoreIndex,
        aead: AeadType,
        msg: &mut [u8],
        aad: &[u8],
        nonce: &[u8],
    ) -> Result<Self::Tag, Self::Error>;
}

/// AEAD Open
pub trait Open {
    /// The key store type used for `Open`.
    type KeyStoreType;

    /// The type of the key store id used, i.e. the type for indexing the database.
    type KeyStoreIndex;

    /// The error type returned by [`Seal`].
    type Error;

    /// The ciphertext and tag input type of [`Seal::open()`].
    type CiphertextTag;

    /// The plaintext return type of [`Seal::open()`].
    type Plaintext;

    /// Decrypt the `cipher_text` with the given parameters and return the plain
    /// text as byte vector.
    fn open(
        key_store: &Self::KeyStoreType,
        key_id: &Self::KeyStoreIndex,
        aead: AeadType,
        cipher_text_tag: &Self::CiphertextTag,
        aad: &[u8],
        nonce: &[u8],
    ) -> Result<Self::Plaintext, Self::Error>;
}
