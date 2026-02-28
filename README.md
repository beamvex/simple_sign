# simple_sign

Simple signing library.

This crate provides a small API for working with cryptographic signatures, including:

- `Signature`: a signature wrapper that stores the raw signature bytes plus the `SigningAlgorithm` used.
- `SigningAlgorithm`: an enum of supported algorithms (see `src/signing_algorithm.rs`).
- Signers: `Ed25519Signer`, `RsaSigner`, and `Secp256k1Signer`.

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
simple_sign = "0.1.1"
```

## Usage

Basic construction and inspection:

```rust
use simple_sign::{Signature, SigningAlgorithm};

let sig = Signature::new_with_algorithm(SigningAlgorithm::ED25519, vec![0u8; 64]);
assert_eq!(sig.get_algorithm(), SigningAlgorithm::ED25519);
let _bytes: &Vec<u8> = sig.get_signature();
```

Signing a hash:

```rust
use base_xx::ByteVec;
use simple_sign::{Ed25519Signer, Signer};
use slahasher::{Hash, HashAlgorithm};

let signer = Ed25519Signer::default();

let data = b"hello";
let bytes = ByteVec::new(data.to_vec());
let hash = Hash::try_hash(&bytes, HashAlgorithm::KECCAK512).unwrap();

let signature = signer.sign(&hash).unwrap();
assert_eq!(signature.get_signature().len(), 64);
```

Serialisation helpers are implemented via `base_xx`’s `Encodable` trait (see `Signature`’s `TryFrom` implementations in `src/signature.rs`).

## Development

Run tests:

```bash
cargo test
```

## License

Licensed under either of:

- Apache License, Version 2.0
- MIT license

at your option.
