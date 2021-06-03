//! # Public and Private Keys
//!
//! This module defines public and private key types that must be used to interact
//! with the key store.
//!
//! FIXME: trait vs types. What do we really need.

#![forbid(unsafe_code, unused_must_use, unstable_features)]
#![deny(
    trivial_casts,
    trivial_numeric_casts,
    missing_docs,
    unused_import_braces,
    unused_extern_crates,
    unused_qualifications
)]

use crypto_algorithms::AsymmetricKeyType;
use key_store::{traits::KeyStoreValue, KeyStoreResult};
use tls_codec::{Deserialize, SecretTlsVecU16, Serialize, TlsDeserialize, TlsSerialize};
use zeroize::Zeroize;

use crate::errors::Error;

/// # AsymmetricKeyError
///
/// This error is thrown when an asymmetric key operation fails.
#[derive(Debug, PartialEq, Eq)]
pub enum AsymmetricKeyError {
    /// The key type is not supported.
    InvalidKeyType(usize),

    /// The key serialization is not valid.
    InvalidSerialization,

    /// An error in the underlying crypto library occurred.
    CryptoLibError(String),
}

/// # Public key
///
/// A public key is a byte vector with an associated `AsymmetricKeyType` and an
/// arbitrary label.
#[cfg_attr(
    feature = "serialization",
    derive(serde::Serialize, serde::Deserialize)
)]
#[derive(Eq, PartialEq, Zeroize, Clone, Debug, TlsSerialize, TlsDeserialize)]
#[zeroize(drop)]
pub struct PublicKey {
    value: SecretTlsVecU16<u8>,
    key_type: AsymmetricKeyType,
    label: SecretTlsVecU16<u8>,
}

impl PublicKey {
    /// Create a new public key from the raw byte values.
    pub fn from(key_type: AsymmetricKeyType, value: &[u8], label: &[u8]) -> Self {
        Self {
            value: value.to_vec().into(),
            key_type,
            label: label.to_vec().into(),
        }
    }

    /// Get the raw public key bytes as byte slice.
    pub fn as_slice(&self) -> &[u8] {
        self.value.as_slice()
    }

    /// Get the `AsymmetricKeyType` of this key.
    pub fn key_type(&self) -> AsymmetricKeyType {
        self.key_type
    }
}

impl KeyStoreValue for PublicKey {
    fn serialize(&self) -> KeyStoreResult<Vec<u8>> {
        Ok(self
            .tls_serialize_detached()
            .map_err(|e| Error::SerializationError(format!("TLS serialization error {:?}", e)))?)
    }

    fn deserialize(raw: &mut [u8]) -> KeyStoreResult<Self> {
        // XXX: can we do this without copy please?
        Ok(Self::tls_deserialize(&mut raw.as_ref()).unwrap())
    }
}
