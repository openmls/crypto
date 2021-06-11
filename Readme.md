# OpenMLS Crypto

This repository holds the crate abstracting crypto primitives for [OpenMLS].
It is based on a key store to store key material, using the [keystore] traits.
Algorithms are defined in the [algorithm-identifiers] crate.

## Traits

- AEAD
- Hashing
- HPKE
- Key generation
- Signatures

To get a list of supported algorithms, the `Supports` trait is provided.

[openmls]: https://github.com/openmls/openmls/
[keystore]: https://github.com/franziskuskiefer/key-store-rs
[algorithm-identifiers]: https://github.com/franziskuskiefer/algorithm-identifiers-rs
