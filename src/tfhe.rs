use crate::torus::Torus;
use crate::tlwe::{TlweSample, TlweSecretKey, TlweParams, TlweKeySwitchKey};
use crate::tgsw::{TgswParams, BootstrappingKey};

#[derive(Debug, Clone)]
pub struct TfheParams {
    pub tlwe_params: TlweParams,
    pub tgsw_params: TgswParams,
    pub n: usize,
    pub N: usize,
    pub k: usize,
}

impl Default for TfheParams {
    fn default() -> Self {
        TfheParams {
            tlwe_params: TlweParams::default(),
            tgsw_params: TgswParams::default(),
            n: 630,
            N: 1024,
            k: 1,
        }
    }
}

#[derive(Debug, Clone)]
pub struct TfheSecretKey {
    pub tlwe_key: TlweSecretKey,
    pub params: TfheParams,
}

impl TfheSecretKey {
    pub fn generate(params: TfheParams) -> Self {
        let tlwe_key = TlweSecretKey::generate_binary(params.tlwe_params.clone());

        TfheSecretKey {
            tlwe_key,
            params,
        }
    }
}

#[derive(Debug, Clone)]
pub struct TfheCloudKey {
    pub bootstrapping_key: BootstrappingKey,
    pub key_switching_key: Option<TlweKeySwitchKey>,
}

impl TfheCloudKey {
    pub fn generate(sk: &TfheSecretKey) -> Self {
        let bootstrapping_key = BootstrappingKey::generate(
            &sk.tlwe_key,
            sk.params.tgsw_params.clone(),
        );

        let key_switching_key = None;

        TfheCloudKey {
            bootstrapping_key,
            key_switching_key,
        }
    }
}

pub struct TfheGates;

impl TfheGates {
    pub fn programmable_bootstrap(
        input: &TlweSample,
        lut: &[Torus],
        bk: &BootstrappingKey,
    ) -> TlweSample {
        let n = bk.n;
        let N = lut.len();

        let mut acc = TlweSample::trivial(&lut[0], input.params.clone());

        for i in 0..n {
            acc = bk.bk[i].cmux(&acc, &acc);
        }

        acc
    }

    pub fn nand(a: &TlweSample, b: &TlweSample, ck: &TfheCloudKey) -> TlweSample {

        let mut result = a.scalar_mul(-1);
        result = result.sub(b);
        let offset = Torus::new(0.625);
        result.b = result.b.add(&offset);

        let mut lut = vec![Torus::new(0.0); 1024];
        for i in 0..512 {
            lut[i] = Torus::new(0.625);
        }
        for i in 512..1024 {
            lut[i] = Torus::new(0.125);
        }

        Self::programmable_bootstrap(&result, &lut, &ck.bootstrapping_key)
    }

    pub fn and(a: &TlweSample, b: &TlweSample, ck: &TfheCloudKey) -> TlweSample {
        let nand_result = Self::nand(a, b, ck);

        Self::not(&nand_result, ck)
    }

    pub fn or(a: &TlweSample, b: &TlweSample, ck: &TfheCloudKey) -> TlweSample {
        let not_a = Self::not(a, ck);
        let not_b = Self::not(b, ck);
        let and_result = Self::and(&not_a, &not_b, ck);
        Self::not(&and_result, ck)
    }

    pub fn xor(a: &TlweSample, b: &TlweSample, ck: &TfheCloudKey) -> TlweSample {

        let mut result = a.sub(b);
        result = result.scalar_mul(2);

        let mut lut = vec![Torus::new(0.0); 1024];
        for i in 256..768 {
            lut[i] = Torus::new(0.625);
        }
        for i in 0..256 {
            lut[i] = Torus::new(0.125);
        }
        for i in 768..1024 {
            lut[i] = Torus::new(0.125);
        }

        Self::programmable_bootstrap(&result, &lut, &ck.bootstrapping_key)
    }

    pub fn not(a: &TlweSample, ck: &TfheCloudKey) -> TlweSample {
        let mut result = a.scalar_mul(-1);
        let offset = Torus::new(0.5);
        result.b = result.b.add(&offset);

        let mut lut = vec![Torus::new(0.0); 1024];
        for i in 0..512 {
            lut[i] = Torus::new(0.625);
        }
        for i in 512..1024 {
            lut[i] = Torus::new(0.125);
        }

        Self::programmable_bootstrap(&result, &lut, &ck.bootstrapping_key)
    }

    pub fn mux(s: &TlweSample, a: &TlweSample, b: &TlweSample, ck: &TfheCloudKey) -> TlweSample {
        let s_and_a = Self::and(s, a, ck);
        let not_s = Self::not(s, ck);
        let not_s_and_b = Self::and(&not_s, b, ck);
        Self::or(&s_and_a, &not_s_and_b, ck)
    }
}

pub struct TfheEncoder;

impl TfheEncoder {
    pub fn encode_bool(value: bool, sk: &TfheSecretKey) -> TlweSample {
        let message = if value {
            Torus::new(0.625)
        } else {
            Torus::new(0.125)
        };
        TlweSample::encrypt(&message, &sk.tlwe_key)
    }

    pub fn decode_bool(sample: &TlweSample, sk: &TfheSecretKey) -> bool {
        sample.decrypt_binary(&sk.tlwe_key)
    }

    pub fn encode_bits(bits: &[bool], sk: &TfheSecretKey) -> Vec<TlweSample> {
        bits.iter()
            .map(|&b| Self::encode_bool(b, sk))
            .collect()
    }

    pub fn decode_bits(samples: &[TlweSample], sk: &TfheSecretKey) -> Vec<bool> {
        samples.iter()
            .map(|s| Self::decode_bool(s, sk))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tfhe_gates() {
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

        let a_true = TfheEncoder::encode_bool(true, &sk);
        let b_true = TfheEncoder::encode_bool(true, &sk);
        let a_false = TfheEncoder::encode_bool(false, &sk);

        let result_and = a_true.add(&b_true);
        let phase = result_and.decrypt_phase(&sk.tlwe_key);
        assert!(phase.value() > 0.5);

        let result_xor = a_true.sub(&a_false);
        let phase_xor = result_xor.decrypt_phase(&sk.tlwe_key);
        assert!(phase_xor.value() > 0.25 && phase_xor.value() < 0.75);
    }

    #[test]
    fn test_encoder_decoder() {
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

        let enc_true = TfheEncoder::encode_bool(true, &sk);
        let dec_true = TfheEncoder::decode_bool(&enc_true, &sk);
        assert_eq!(dec_true, true);

        let enc_false = TfheEncoder::encode_bool(false, &sk);
        let dec_false = TfheEncoder::decode_bool(&enc_false, &sk);
        assert_eq!(dec_false, false);

        let bits = vec![true, false, true, true, false];
        let encoded = TfheEncoder::encode_bits(&bits, &sk);
        let decoded = TfheEncoder::decode_bits(&encoded, &sk);
        assert_eq!(decoded, bits);
    }
}