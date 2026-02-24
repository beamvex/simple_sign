# simple_sign

Simple signing library.

This crate provides a small API for working with cryptographic signatures, including:

- `Signature`: a signature wrapper that stores the raw signature bytes plus the `SigningAlgorithm` used.
- `SigningAlgorithm`: an enum of supported algorithms (see `src/signing_algorithm.rs`).

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
simple_sign = "0.0.1"
```

## Usage

Basic construction and inspection:

```rust
use simple_sign::{Signature, SigningAlgorithm};

let sig = Signature::new_with_algorithm(SigningAlgorithm::ED25519, vec![0u8; 64]);
assert_eq!(sig.get_algorithm(), SigningAlgorithm::ED25519);
let _bytes: &Vec<u8> = sig.get_signature();
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
