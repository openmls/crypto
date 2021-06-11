//! # OpenMLS Crypto traits
//!
//! This crate defines traits abstracting the crypto primitives used by OpenMLS.
//! The traits are defined to be used with a [`key_store`](https://github.com/franziskuskiefer/key-store-rs) implementation but
//! do not necessarily have to use one.

use crypto_algorithms::{AsymmetricKeyType, SymmetricKeyType};

pub mod aead;
pub mod hash;
pub mod hkdf;
pub mod hpke;
pub mod key_generation;
pub mod signature;

/// Check whether the key store supports certain functionality.
pub trait Supports {
    fn symmetric_key_types() -> Vec<SymmetricKeyType>
    where
        Self: Sized;
    fn asymmetric_key_types() -> Vec<AsymmetricKeyType>
    where
        Self: Sized;
}
