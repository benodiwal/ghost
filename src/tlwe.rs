use rand::Rng;
use crate::torus::Torus;
use crate::noise::gaussian_noise;

#[derive(Debug, Clone)]
pub struct TlweParams {
    pub n: usize,
    pub stddev: f64,
}

impl Default for TlweParams {
    fn default() -> Self {
        TlweParams {
            n: 630,
            stddev: 2.0e-9,
        }
    }
}

#[derive(Debug, Clone)]
pub struct TlweSecretKey {
    pub coeffs: Vec<i32>,
    pub params: TlweParams,
}

impl TlweSecretKey {
    pub fn generate_binary(params: TlweParams) -> Self {
        let mut rng = rand::rng();
        let coeffs: Vec<i32> = (0..params.n)
            .map(|_| if rng.random_bool(0.5) { 1 } else { 0 })
            .collect();

        TlweSecretKey { coeffs, params }
    }

    pub fn generate_ternary(params: TlweParams) -> Self {
        let mut rng = rand::rng();
        let coeffs: Vec<i32> = (0..params.n)
            .map(|_| {
                let r: f64 = rng.random();
                if r < 0.333 { -1 }
                else if r < 0.667 { 0 }
                else { 1 }
            })
            .collect();

        TlweSecretKey { coeffs, params }
    }
}

#[derive(Debug, Clone)]
pub struct TlweSample {
    pub a: Vec<Torus>,
    pub b: Torus,
    pub params: TlweParams,
}

impl TlweSample {
    pub fn encrypt(message: &Torus, sk: &TlweSecretKey) -> Self {
        let mut rng = rand::rng();

        let a: Vec<Torus> = (0..sk.params.n)
            .map(|_| Torus::new(rng.random::<f64>()))
            .collect();

        let mut inner_product = 0.0;
        for i in 0..sk.params.n {
            inner_product += a[i].value() * (sk.coeffs[i] as f64);
        }

        let error = gaussian_noise(sk.params.stddev);
        let b = Torus::new(inner_product + message.value() + error);

        TlweSample {
            a,
            b,
            params: sk.params.clone(),
        }
    }

    pub fn decrypt_phase(&self, sk: &TlweSecretKey) -> Torus {
        let mut inner_product = 0.0;
        for i in 0..sk.params.n {
            inner_product += self.a[i].value() * (sk.coeffs[i] as f64);
        }

        Torus::new(self.b.value() - inner_product)
    }

    pub fn decrypt_binary(&self, sk: &TlweSecretKey) -> bool {
        let phase = self.decrypt_phase(sk);
        phase.value() > 0.25 && phase.value() < 0.75
    }

    pub fn add(&self, other: &TlweSample) -> TlweSample {
        assert_eq!(self.params.n, other.params.n);

        let a: Vec<Torus> = self.a.iter()
            .zip(other.a.iter())
            .map(|(x, y)| x.add(y))
            .collect();

        let b = self.b.add(&other.b);

        TlweSample {
            a,
            b,
            params: self.params.clone(),
        }
    }

    pub fn sub(&self, other: &TlweSample) -> TlweSample {
        assert_eq!(self.params.n, other.params.n);

        let a: Vec<Torus> = self.a.iter()
            .zip(other.a.iter())
            .map(|(x, y)| x.sub(y))
            .collect();

        let b = self.b.sub(&other.b);

        TlweSample {
            a,
            b,
            params: self.params.clone(),
        }
    }

    pub fn scalar_mul(&self, scalar: i32) -> TlweSample {
        let a: Vec<Torus> = self.a.iter()
            .map(|x| x.mul_scalar(scalar as f64))
            .collect();

        let b = self.b.mul_scalar(scalar as f64);

        TlweSample {
            a,
            b,
            params: self.params.clone(),
        }
    }

    pub fn trivial(message: &Torus, params: TlweParams) -> Self {
        let a = vec![Torus::new(0.0); params.n];
        let b = message.clone();

        TlweSample { a, b, params }
    }

    pub fn extract_from_trlwe(trlwe_a: &[Vec<Torus>], trlwe_b: &Torus, _index: usize) -> Self {
        let n = trlwe_a[0].len();
        let params = TlweParams { n, stddev: 1e-9 };

        let a = trlwe_a[0].clone();
        let b = *trlwe_b;

        TlweSample { a, b, params }
    }
}

#[derive(Debug, Clone)]
pub struct TlweKeySwitchKey {
    pub samples: Vec<Vec<TlweSample>>,
    pub n: usize,
    pub t: usize,
    pub base_bit: u32,
}

impl TlweKeySwitchKey {
    pub fn generate(
        key_in: &TlweSecretKey,
        key_out: &TlweSecretKey,
        t: usize,
        base_bit: u32,
    ) -> Self {
        let n = key_in.params.n;
        let mut samples = vec![vec![]; n];

        for i in 0..n {
            samples[i] = Vec::with_capacity(t);
            for j in 0..t {
                let message_value = (key_in.coeffs[i] as f64) / (1u64 << (j as u32 * base_bit)) as f64;
                let message = Torus::new(message_value);
                samples[i].push(TlweSample::encrypt(&message, key_out));
            }
        }

        TlweKeySwitchKey {
            samples,
            n,
            t,
            base_bit,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tlwe_encrypt_decrypt_binary() {
        let params = TlweParams {
            n: 10,
            stddev: 1e-9,
        };

        let sk = TlweSecretKey::generate_binary(params.clone());

        let m0 = Torus::new(0.0);
        let ct0 = TlweSample::encrypt(&m0, &sk);
        assert!(!ct0.decrypt_binary(&sk));

        let m1 = Torus::new(0.5);
        let ct1 = TlweSample::encrypt(&m1, &sk);
        assert!(ct1.decrypt_binary(&sk));
    }

    #[test]
    fn test_tlwe_homomorphic_ops() {
        let params = TlweParams {
            n: 10,
            stddev: 1e-9,
        };

        let sk = TlweSecretKey::generate_binary(params.clone());

        let m1 = Torus::new(0.1);
        let m2 = Torus::new(0.2);

        let ct1 = TlweSample::encrypt(&m1, &sk);
        let ct2 = TlweSample::encrypt(&m2, &sk);

        let ct_sum = ct1.add(&ct2);
        let phase_sum = ct_sum.decrypt_phase(&sk);
        assert!((phase_sum.value() - 0.3).abs() < 1e-6);

        let ct_scaled = ct1.scalar_mul(3);
        let phase_scaled = ct_scaled.decrypt_phase(&sk);
        assert!((phase_scaled.value() - 0.3).abs() < 1e-6);
    }
}