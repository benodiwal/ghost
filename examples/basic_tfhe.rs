use ghost_tfhe::lwe::{LweParams, LweSecretKey, LweCiphertext};
use ghost_tfhe::tlwe::{TlweParams, TlweSecretKey, TlweSample};
use ghost_tfhe::torus::Torus;
use ghost_tfhe::tfhe::{TfheParams, TfheSecretKey, TfheEncoder};

fn main() {
    println!("=== Basic TFHE Implementation Demo ===\n");

    // 1. Basic LWE Example
    println!("1. Basic LWE Encryption:");
    let lwe_params = LweParams {
        n: 10,
        q: 1024,
        stddev: 1.0,
    };

    let lwe_sk = LweSecretKey::generate_binary(lwe_params.clone());

    let message1 = 42;
    let message2 = 17;

    let ct1 = LweCiphertext::encrypt(message1, &lwe_sk);
    let ct2 = LweCiphertext::encrypt(message2, &lwe_sk);

    println!("  Original messages: {} and {}", message1, message2);

    // Homomorphic addition
    let ct_sum = ct1.add(&ct2);
    let decrypted_sum = ct_sum.decrypt(&lwe_sk);
    println!("  Homomorphic sum result: {} (expected: {})", decrypted_sum, message1 + message2);
    println!("  Error: {}\n", (decrypted_sum as i64 - (message1 + message2) as i64).abs());

    // 2. TLWE (Torus LWE) Example
    println!("2. TLWE Encryption on the Torus:");
    let tlwe_params = TlweParams {
        n: 10,
        stddev: 1e-9,
    };

    let tlwe_sk = TlweSecretKey::generate_binary(tlwe_params.clone());

    // Encrypt boolean values (0 or 1)
    let m0 = Torus::new(0.0);  // Encodes 0
    let m1 = Torus::new(0.5);  // Encodes 1

    let tlwe_ct0 = TlweSample::encrypt(&m0, &tlwe_sk);
    let tlwe_ct1 = TlweSample::encrypt(&m1, &tlwe_sk);

    let dec0 = tlwe_ct0.decrypt_binary(&tlwe_sk);
    let dec1 = tlwe_ct1.decrypt_binary(&tlwe_sk);

    println!("  Encrypted 0, decrypted: {}", dec0);
    println!("  Encrypted 1, decrypted: {}\n", dec1);

    // 3. TFHE Boolean Operations
    println!("3. TFHE Boolean Encryption:");
    let tfhe_params = TfheParams {
        tlwe_params: TlweParams {
            n: 10,
            stddev: 1e-9,
        },
        tgsw_params: Default::default(),
        n: 10,
        N: 32,
        k: 1,
    };

    let tfhe_sk = TfheSecretKey::generate(tfhe_params);

    // Encode boolean values
    let enc_true = TfheEncoder::encode_bool(true, &tfhe_sk);
    let enc_false = TfheEncoder::encode_bool(false, &tfhe_sk);

    // Decrypt to verify
    let dec_true = TfheEncoder::decode_bool(&enc_true, &tfhe_sk);
    let dec_false = TfheEncoder::decode_bool(&enc_false, &tfhe_sk);

    println!("  Encrypted true, decrypted: {}", dec_true);
    println!("  Encrypted false, decrypted: {}\n", dec_false);

    // 4. Homomorphic operations on TLWE
    println!("4. Homomorphic Operations on TLWE:");
    let val1 = Torus::new(0.1);
    let val2 = Torus::new(0.2);

    let ct1 = TlweSample::encrypt(&val1, &tlwe_sk);
    let ct2 = TlweSample::encrypt(&val2, &tlwe_sk);

    // Homomorphic addition
    let ct_add = ct1.add(&ct2);
    let phase_add = ct_add.decrypt_phase(&tlwe_sk);
    println!("  0.1 + 0.2 = {} (expected: ~0.3)", phase_add.value());

    // Scalar multiplication
    let ct_scaled = ct1.scalar_mul(3);
    let phase_scaled = ct_scaled.decrypt_phase(&tlwe_sk);
    println!("  0.1 * 3 = {} (expected: ~0.3)", phase_scaled.value());

    println!("\n=== Demo Complete ===");
    println!("\nThis implementation includes:");
    println!("- Basic LWE encryption with lattice-based security");
    println!("- TLWE operations on the torus");
    println!("- TGSW for bootstrapping");
    println!("- Homomorphic boolean gates (NAND, AND, OR, XOR, NOT, MUX)");
    println!("- Homomorphic arithmetic (addition, scalar multiplication)");
}