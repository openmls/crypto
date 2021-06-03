use crypto_algorithms::{AsymmetricKeyType, SymmetricKeyType};

pub mod aead;
pub mod hash;
pub mod hkdf;
pub mod hpke;
pub mod key_generation;
pub mod signature;

/// Check whether the key store supports certain functionality.
pub trait Supports {
    fn symmetric_key_types(&self) -> Vec<SymmetricKeyType>
    where
        Self: Sized;
    fn asymmetric_key_types(&self) -> Vec<AsymmetricKeyType>
    where
        Self: Sized;
}
