use crypto_algorithms::{AsymmetricKeyType, SymmetricKeyType};
use key_store::types::Status;

use crate::{errors::Error, hash::Hash, types::keys::PublicKey, Supports};

/// Generate keys.
pub trait GenerateKeys: Hash + Supports {
    /// The key store type used for `Seal`.
    type KeyStoreType;

    /// The type of the key store id used, i.e. the type for indexing the database.
    type KeyStoreIndex;

    fn new_secret(
        key_store: &Self::KeyStoreType,
        key_type: SymmetricKeyType,
        status: Status,
        k: &Self::KeyStoreIndex,
        label: &[u8],
    ) -> Result<(), Error>;

    /// Generate a new key pair and return the [`PublicKey`] as well as the
    /// identifier of the private key in the key store.
    fn new_key_pair(
        key_store: &Self::KeyStoreType,
        key_type: AsymmetricKeyType,
        status: Status,
        label: &[u8],
    ) -> Result<(PublicKey, Self::KeyStoreIndex), Error>;
}
