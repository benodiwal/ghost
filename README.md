# Ghost-TFHE

A pure Rust implementation of TFHE (Torus Fully Homomorphic Encryption) for secure computation on encrypted data.

## Features

- **LWE (Learning With Errors)** - Basic lattice-based encryption
- **TLWE (Torus LWE)** - Operations on the torus for improved efficiency
- **TGSW (Torus GSW)** - Bootstrapping operations
- **TFHE** - Complete fully homomorphic encryption scheme
- **Homomorphic Operations** - Boolean gates (AND, OR, XOR, NAND, NOT, MUX) and arithmetic

## Quick Start

Add to your `Cargo.toml`:

```toml
[dependencies]
ghost-tfhe = "0.1.0"
```

### Basic Example

```rust
use ghost_tfhe::tfhe::{TfheParams, TfheSecretKey, TfheEncoder};

fn main() {
    // Generate parameters and keys
    let params = TfheParams::default();
    let secret_key = TfheSecretKey::generate(params);

    // Encrypt boolean values
    let encrypted_true = TfheEncoder::encode_bool(true, &secret_key);
    let encrypted_false = TfheEncoder::encode_bool(false, &secret_key);

    // Decrypt and verify
    let decrypted_true = TfheEncoder::decode_bool(&encrypted_true, &secret_key);
    let decrypted_false = TfheEncoder::decode_bool(&encrypted_false, &secret_key);

    println!("true -> {}", decrypted_true);
    println!("false -> {}", decrypted_false);
}
```

## Examples

Run the basic demo:

```bash
cargo run --example basic_tfhe
```

## Architecture

- `torus.rs` - Torus arithmetic operations
- `noise.rs` - Noise management for security
- `encoding.rs` - Message encoding/decoding
- `lwe.rs` - LWE encryption primitives
- `tlwe.rs` - Torus LWE operations
- `tgsw.rs` - TGSW scheme for bootstrapping
- `tfhe.rs` - Main TFHE implementation
- `operations.rs` - Homomorphic operations

## Security

This implementation uses lattice-based cryptography with configurable noise parameters for quantum-resistant security.

## License

MIT
