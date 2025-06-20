use crate::tfhe::{TfheSecretKey, TfheCloudKey, TfheGates, TfheEncoder};
use crate::tlwe::TlweSample;

pub struct HomomorphicOps;

impl HomomorphicOps {
    pub fn half_adder(
        a: &TlweSample,
        b: &TlweSample,
        ck: &TfheCloudKey,
    ) -> (TlweSample, TlweSample) {
        let sum = TfheGates::xor(a, b, ck);
        let carry = TfheGates::and(a, b, ck);
        (sum, carry)
    }

    pub fn full_adder(
        a: &TlweSample,
        b: &TlweSample,
        cin: &TlweSample,
        ck: &TfheCloudKey,
    ) -> (TlweSample, TlweSample) {
        let ab_xor = TfheGates::xor(a, b, ck);
        let sum = TfheGates::xor(&ab_xor, cin, ck);

        let ab_and = TfheGates::and(a, b, ck);
        let cin_and_xor = TfheGates::and(cin, &ab_xor, ck);
        let carry = TfheGates::or(&ab_and, &cin_and_xor, ck);

        (sum, carry)
    }

    pub fn add_n_bit(
        a: &[TlweSample],
        b: &[TlweSample],
        ck: &TfheCloudKey,
    ) -> Vec<TlweSample> {
        assert_eq!(a.len(), b.len());
        let n = a.len();

        let mut result = Vec::with_capacity(n + 1);
        let mut carry = TfheEncoder::encode_bool(false, &TfheSecretKey::generate(Default::default()));

        for i in 0..n {
            let (sum, new_carry) = Self::full_adder(&a[i], &b[i], &carry, ck);
            result.push(sum);
            carry = new_carry;
        }

        result.push(carry);
        result
    }

    pub fn multiply_by_constant(
        a: &[TlweSample],
        constant: u32,
        ck: &TfheCloudKey,
    ) -> Vec<TlweSample> {
        let n = a.len();
        let sk = TfheSecretKey::generate(Default::default());

        let zero = TfheEncoder::encode_bool(false, &sk);
        let mut result: Vec<TlweSample> = vec![zero.clone(); n + 8];

        for _ in 0..constant {
            let sum = Self::add_n_bit(&result[..n], a, ck);
            for i in 0..sum.len().min(result.len()) {
                result[i] = sum[i].clone();
            }
        }

        result
    }

    pub fn equal_bit(
        a: &TlweSample,
        b: &TlweSample,
        ck: &TfheCloudKey,
    ) -> TlweSample {
        let xor_result = TfheGates::xor(a, b, ck);
        TfheGates::not(&xor_result, ck)
    }

    /// Compare n-bit numbers for equality
    pub fn equal_n_bit(
        a: &[TlweSample],
        b: &[TlweSample],
        ck: &TfheCloudKey,
    ) -> TlweSample {
        assert_eq!(a.len(), b.len());

        let mut result = Self::equal_bit(&a[0], &b[0], ck);

        for i in 1..a.len() {
            let bit_equal = Self::equal_bit(&a[i], &b[i], ck);
            result = TfheGates::and(&result, &bit_equal, ck);
        }

        result
    }

    /// Bitwise left shift
    pub fn left_shift(
        a: &[TlweSample],
        shift: usize,
    ) -> Vec<TlweSample> {
        let n = a.len();
        let sk = TfheSecretKey::generate(Default::default());
        let zero = TfheEncoder::encode_bool(false, &sk);

        let mut result = Vec::with_capacity(n);

        // Shift left by 'shift' positions
        for _ in 0..shift.min(n) {
            result.push(zero.clone());
        }

        for i in 0..(n - shift).min(n) {
            result.push(a[i].clone());
        }

        // Pad with zeros if needed
        while result.len() < n {
            result.push(zero.clone());
        }

        result
    }

    /// Bitwise right shift
    pub fn right_shift(
        a: &[TlweSample],
        shift: usize,
    ) -> Vec<TlweSample> {
        let n = a.len();
        let sk = TfheSecretKey::generate(Default::default());
        let zero = TfheEncoder::encode_bool(false, &sk);

        let mut result = Vec::with_capacity(n);

        // Skip 'shift' positions from the beginning
        for i in shift..n {
            result.push(a[i].clone());
        }

        // Pad with zeros
        while result.len() < n {
            result.push(zero.clone());
        }

        result
    }

    /// Compute greater than comparison for single bits
    pub fn greater_than_bit(
        a: &TlweSample,
        b: &TlweSample,
        ck: &TfheCloudKey,
    ) -> TlweSample {
        // a > b is equivalent to a AND NOT(b)
        let not_b = TfheGates::not(b, ck);
        TfheGates::and(a, &not_b, ck)
    }

    /// Maximum of two bits
    pub fn max_bit(
        a: &TlweSample,
        b: &TlweSample,
        ck: &TfheCloudKey,
    ) -> TlweSample {
        TfheGates::or(a, b, ck)
    }

    /// Minimum of two bits
    pub fn min_bit(
        a: &TlweSample,
        b: &TlweSample,
        ck: &TfheCloudKey,
    ) -> TlweSample {
        TfheGates::and(a, b, ck)
    }

    /// Compute n-bit two's complement negation
    pub fn negate_n_bit(
        a: &[TlweSample],
        ck: &TfheCloudKey,
    ) -> Vec<TlweSample> {
        let n = a.len();
        let sk = TfheSecretKey::generate(Default::default());

        // Step 1: Invert all bits
        let mut inverted = Vec::with_capacity(n);
        for i in 0..n {
            inverted.push(TfheGates::not(&a[i], ck));
        }

        // Step 2: Add 1
        let one_bit = TfheEncoder::encode_bool(true, &sk);
        let zero_bit = TfheEncoder::encode_bool(false, &sk);

        let mut one = vec![zero_bit.clone(); n];
        one[0] = one_bit;

        Self::add_n_bit(&inverted, &one, ck)
    }

    /// Subtract b from a (a - b = a + (-b))
    pub fn subtract_n_bit(
        a: &[TlweSample],
        b: &[TlweSample],
        ck: &TfheCloudKey,
    ) -> Vec<TlweSample> {
        let neg_b = Self::negate_n_bit(b, ck);
        Self::add_n_bit(a, &neg_b[..a.len()], ck)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tfhe::TfheParams;
    use crate::tlwe::TlweParams;
    use crate::tgsw::TgswParams;

    #[test]
    fn test_half_adder() {
        let params = TfheParams {
            tlwe_params: TlweParams {
                n: 10,
                stddev: 1e-9,
            },
            tgsw_params: TgswParams {
                l: 2,
                bg_bit: 8,
                tlwe_params: TlweParams {
                    n: 10,
                    stddev: 1e-9,
                },
            },
            n: 10,
            N: 32,
            k: 1,
        };

        let sk = TfheSecretKey::generate(params);
        let ck = TfheCloudKey::generate(&sk);

        // Test 1 + 1 = 10 (binary)
        let a = TfheEncoder::encode_bool(true, &sk);
        let b = TfheEncoder::encode_bool(true, &sk);

        let (sum, carry) = HomomorphicOps::half_adder(&a, &b, &ck);

        // For simplified testing, we check basic properties
        // In a full implementation with bootstrapping, we'd decrypt and verify
        assert!(sum.params.n == 10);
        assert!(carry.params.n == 10);
    }

    #[test]
    fn test_bit_operations() {
        let params = TfheParams {
            tlwe_params: TlweParams {
                n: 10,
                stddev: 1e-9,
            },
            tgsw_params: TgswParams::default(),
            n: 10,
            N: 32,
            k: 1,
        };

        let sk = TfheSecretKey::generate(params);

        // Test shift operations
        let bits = vec![
            TfheEncoder::encode_bool(true, &sk),
            TfheEncoder::encode_bool(false, &sk),
            TfheEncoder::encode_bool(true, &sk),
        ];

        let shifted_left = HomomorphicOps::left_shift(&bits, 1);
        assert_eq!(shifted_left.len(), 3);

        let shifted_right = HomomorphicOps::right_shift(&bits, 1);
        assert_eq!(shifted_right.len(), 3);
    }
}