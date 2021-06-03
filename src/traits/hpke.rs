use crypto_algorithms::{AeadType, KdfType};

use crate::{errors::Error, keys::PublicKey};

type KemOutput = Vec<u8>;
type Ciphertext = Vec<u8>;
type Plaintext = Vec<u8>;

/// HPKE
/// Note that his trait only holds a very limited subset of HPKE.
/// Only single-shot, base-mode HPKE is supported for now.
pub trait HpkeSeal {
    /// The key store type used for `Seal`.
    type KeyStoreType;

    /// The type of the key store id used, i.e. the type for indexing the database.
    type KeyStoreIndex;

    /// Encrypt the `payload` to the public key stored for `key_id`.
    fn hpke_seal(
        key_store: &Self::KeyStoreType,
        kdf: KdfType,
        aead: AeadType,
        key_id: &Self::KeyStoreIndex,
        info: &[u8],
        aad: &[u8],
        payload: &[u8],
    ) -> Result<(Ciphertext, KemOutput), Error>;

    /// Encrypt the `payload` to the public `key`.
    fn hpke_seal_to_pk(
        key_store: &Self::KeyStoreType,
        kdf: KdfType,
        aead: AeadType,
        key: &PublicKey,
        info: &[u8],
        aad: &[u8],
        payload: &[u8],
    ) -> Result<(Ciphertext, KemOutput), Error>;

    /// Encrypt the secret stored for `secret_id` to the public key stored for `key_id`.
    fn hpke_seal_secret(
        key_store: &Self::KeyStoreType,
        kdf: KdfType,
        aead: AeadType,
        key_id: &Self::KeyStoreIndex,
        info: &[u8],
        aad: &[u8],
        secret_id: &Self::KeyStoreIndex,
    ) -> Result<(Ciphertext, KemOutput), Error>;

    /// Encrypt the secret stored for `secret_id` to the public `key`.
    fn hpke_seal_secret_to_pk(
        key_store: &Self::KeyStoreType,
        kdf: KdfType,
        aead: AeadType,
        key: &PublicKey,
        info: &[u8],
        aad: &[u8],
        secret_id: &Self::KeyStoreIndex,
    ) -> Result<(Ciphertext, KemOutput), Error>;
}

pub trait HpkeOpen {
    /// The key store type used for `Seal`.
    type KeyStoreType;

    /// The type of the key store id used, i.e. the type for indexing the database.
    type KeyStoreIndex;

    /// Open an HPKE `cipher_text` with the private key of the given `key_id`.
    fn hpke_open_with_sk(
        key_store: &Self::KeyStoreType,
        kdf: KdfType,
        aead: AeadType,
        key_id: &Self::KeyStoreIndex,
        cipher_text: &[u8],
        kem: &KemOutput,
        info: &[u8],
        aad: &[u8],
    ) -> Result<Plaintext, Error>;
}

/// XXX: We really only need the KEM type here. But hpke-rs needs all of it
pub trait HpkeDerive {
    /// The key store type used for `Seal`.
    type KeyStoreType;

    /// The type of the key store id used, i.e. the type for indexing the database.
    type KeyStoreIndex;

    /// Derive a new HPKE keypair from the secret at `ikm_id`.
    fn derive_key_pair(
        key_store: &Self::KeyStoreType,
        kem: KdfType,
        kdf: KdfType,
        aead: AeadType,
        ikm_id: &Self::KeyStoreIndex,
        private_key_id: &Self::KeyStoreIndex,
        label: &[u8],
    ) -> Result<PublicKey, Error>;
}
