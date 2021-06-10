use crypto_algorithms::{AeadType, KdfType, KemType};

/// HPKE
/// Note that his trait only holds a very limited subset of HPKE.
/// Only single-shot, base-mode HPKE is supported for now.
pub trait HpkeSeal {
    /// The key store type used for [`HpkeSeal`].
    type KeyStoreType;

    /// The type of the key store id used, i.e. the type for indexing the database.
    type KeyStoreIndex;

    /// The type of the KEM output.
    type KemOutput;

    /// The type of the ciphertext output.
    type Ciphertext;

    /// The type of the plaintext input.
    type Plaintext;

    /// The type of the public key input.
    type PublicKey;

    /// The error type returned by [`HpkeSeal`].
    type Error;

    /// Encrypt the `payload` to the public key stored for `key_id`.
    fn hpke_seal(
        key_store: &Self::KeyStoreType,
        kdf: KdfType,
        aead: AeadType,
        key_id: &Self::KeyStoreIndex,
        info: &[u8],
        aad: &[u8],
        payload: &Self::Plaintext,
    ) -> Result<(Self::Ciphertext, Self::KemOutput), Self::Error>;

    /// Encrypt the `payload` to the public `key`.
    fn hpke_seal_to_pk(
        kdf: KdfType,
        aead: AeadType,
        key: &Self::PublicKey,
        info: &[u8],
        aad: &[u8],
        payload: &Self::Plaintext,
    ) -> Result<(Self::Ciphertext, Self::KemOutput), Self::Error>;

    /// Encrypt the secret stored for `secret_id` to the public key stored for `key_id`.
    fn hpke_seal_secret(
        key_store: &Self::KeyStoreType,
        kdf: KdfType,
        aead: AeadType,
        key_id: &Self::KeyStoreIndex,
        info: &[u8],
        aad: &[u8],
        secret_id: &Self::KeyStoreIndex,
    ) -> Result<(Self::Ciphertext, Self::KemOutput), Self::Error>;

    /// Encrypt the secret stored for `secret_id` to the public `key`.
    fn hpke_seal_secret_to_pk(
        key_store: &Self::KeyStoreType,
        kdf: KdfType,
        aead: AeadType,
        key: &Self::PublicKey,
        info: &[u8],
        aad: &[u8],
        secret_id: &Self::KeyStoreIndex,
    ) -> Result<(Self::Ciphertext, Self::KemOutput), Self::Error>;
}

pub trait HpkeOpen {
    /// The key store type used for [`HpkeOpen`].
    type KeyStoreType;

    /// The type of the key store id used, i.e. the type for indexing the database.
    type KeyStoreIndex;

    /// The type of the plaintext output.
    type Plaintext;

    /// The type of the ciphertext input.
    type Ciphertext;

    /// The type of the KEM input.
    type KemInput;

    /// The error type returned by [`HpkeOpen`].
    type Error;

    /// Open an HPKE `cipher_text` with the private key of the given `key_id`.
    fn hpke_open_with_sk(
        key_store: &Self::KeyStoreType,
        kdf: KdfType,
        aead: AeadType,
        key_id: &Self::KeyStoreIndex,
        cipher_text: &Self::Ciphertext,
        kem: &Self::KemInput,
        info: &[u8],
        aad: &[u8],
    ) -> Result<Self::Plaintext, Self::Error>;
}

/// XXX: We really only need the KEM type here. But hpke-rs needs all of it
pub trait HpkeDerive {
    /// The key store type used for `Seal`.
    type KeyStoreType;

    /// The type of the key store id used, i.e. the type for indexing the database.
    type KeyStoreIndex;

    /// The type of the public key output.
    type PublicKey;

    /// The error type returned by [`HpkeDerive`].
    type Error;

    /// Derive a new HPKE keypair from the secret at `ikm_id`.
    fn derive_key_pair(
        key_store: &Self::KeyStoreType,
        kem: KemType,
        kdf: KdfType,
        aead: AeadType,
        ikm_id: &Self::KeyStoreIndex,
        label: &[u8],
    ) -> Result<(Self::PublicKey, Self::KeyStoreIndex), Self::Error>;
}
