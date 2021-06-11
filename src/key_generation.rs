use crypto_algorithms::{AsymmetricKeyType, SymmetricKeyType};
use key_store::types::Status;

use crate::Supports;

/// Generate keys.
pub trait GenerateKeys: Supports {
    /// The key store type used for [`GenerateKeys`].
    type KeyStoreType;

    /// The type of the key store id used, i.e. the type for indexing the database.
    type KeyStoreIndex;

    /// The type of the public key generated and returned.
    type PublicKey;

    /// The error type returned by [`GenerateKeys`].
    type Error;

    fn new_secret(
        key_store: &Self::KeyStoreType,
        key_type: SymmetricKeyType,
        status: Status,
        k: &Self::KeyStoreIndex,
        label: &[u8],
    ) -> Result<(), Self::Error>;

    /// Generate a new key pair and return the [`GenerateKeys::PublicKey`] as well as the
    /// identifier of the private key in the key store.
    fn new_key_pair(
        key_store: &Self::KeyStoreType,
        key_type: AsymmetricKeyType,
        status: Status,
        label: &[u8],
    ) -> Result<(Self::PublicKey, Self::KeyStoreIndex), Self::Error>;
}
