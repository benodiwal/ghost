use crate::torus::Torus;
use crate::tlwe::{TlweSample, TlweSecretKey, TlweParams};

#[derive(Debug, Clone)]
pub struct TgswParams {
    pub l: usize,
    pub bg_bit: u32,
    pub tlwe_params: TlweParams,
}

impl Default for TgswParams {
    fn default() -> Self {
        TgswParams {
            l: 3,
            bg_bit: 10,
            tlwe_params: TlweParams::default(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct TgswSample {
    pub samples: Vec<Vec<TlweSample>>,
    pub k: usize,
    pub l: usize,
    pub params: TgswParams,
}

impl TgswSample {
    pub fn encrypt(message: i32, sk: &TlweSecretKey, params: TgswParams) -> Self {
        let k = 1;
        let l = params.l;
        let bg = 1u64 << params.bg_bit;

        let mut samples = vec![vec![]; k + 1];

        for i in 0..=k {
            samples[i] = Vec::with_capacity(l);
            for j in 0..l {
                let h_value = 1.0 / (bg.pow(j as u32 + 1) as f64);

                let msg_value = if i == 0 {
                    -(sk.coeffs[0] as f64) * (message as f64) * h_value
                } else {
                    (message as f64) * h_value
                };

                let msg_torus = Torus::new(msg_value);

                samples[i].push(TlweSample::encrypt(&msg_torus, sk));
            }
        }

        TgswSample {
            samples,
            k,
            l,
            params,
        }
    }

    pub fn trivial(message: i32, params: TgswParams) -> Self {
        let k = 1;
        let l = params.l;
        let bg = 1u64 << params.bg_bit;

        let mut samples = vec![vec![]; k + 1];

        for i in 0..=k {
            samples[i] = Vec::with_capacity(l);
            for j in 0..l {
                let h_value = 1.0 / (bg.pow(j as u32 + 1) as f64);
                let msg_value = if i == k {
                    (message as f64) * h_value
                } else {
                    0.0
                };

                let msg_torus = Torus::new(msg_value);
                samples[i].push(TlweSample::trivial(&msg_torus, params.tlwe_params.clone()));
            }
        }

        TgswSample {
            samples,
            k,
            l,
            params,
        }
    }

    pub fn decompose(value: &Torus, params: &TgswParams) -> Vec<i32> {
        let bg = 1u64 << params.bg_bit;
        let half_bg = (bg / 2) as i32;

        let mut result = Vec::with_capacity(params.l);
        let mut v = (value.value() * (1u64 << 32) as f64) as i64;

        for _ in 0..params.l {
            let digit = ((v % bg as i64) as i32) - half_bg;
            result.push(digit);
            v /= bg as i64;
        }

        result
    }

    pub fn external_product(&self, tlwe: &TlweSample) -> TlweSample {
        let mut decomposed_a = Vec::with_capacity(self.params.tlwe_params.n);
        for i in 0..self.params.tlwe_params.n {
            decomposed_a.push(Self::decompose(&tlwe.a[i], &self.params));
        }
        let decomposed_b = Self::decompose(&tlwe.b, &self.params);

        let mut result_a = vec![Torus::new(0.0); self.params.tlwe_params.n];
        let mut result_b = Torus::new(0.0);

        for i in 0..=self.k {
            for j in 0..self.l {
                if i < self.k {
                    for idx in 0..self.params.tlwe_params.n {
                        let scalar = decomposed_a[i][j];
                        result_a[idx] = result_a[idx].add(
                            &self.samples[i][j].a[idx].mul_scalar(scalar as f64)
                        );
                    }
                    result_b = result_b.add(
                        &self.samples[i][j].b.mul_scalar(decomposed_a[i][j] as f64)
                    );
                } else {
                    for idx in 0..self.params.tlwe_params.n {
                        result_a[idx] = result_a[idx].add(
                            &self.samples[i][j].a[idx].mul_scalar(decomposed_b[j] as f64)
                        );
                    }
                    result_b = result_b.add(
                        &self.samples[i][j].b.mul_scalar(decomposed_b[j] as f64)
                    );
                }
            }
        }

        TlweSample {
            a: result_a,
            b: result_b,
            params: self.params.tlwe_params.clone(),
        }
    }

    pub fn cmux(&self, c0: &TlweSample, c1: &TlweSample) -> TlweSample {
        let diff = c1.sub(c0);

        let product = self.external_product(&diff);

        product.add(c0)
    }
}

#[derive(Debug, Clone)]
pub struct BootstrappingKey {
    pub bk: Vec<TgswSample>,
    pub n: usize,
    pub params: TgswParams,
}

impl BootstrappingKey {
    pub fn generate(sk: &TlweSecretKey, params: TgswParams) -> Self {
        let n = sk.params.n;
        let mut bk = Vec::with_capacity(n);

        for i in 0..n {
            bk.push(TgswSample::encrypt(sk.coeffs[i], sk, params.clone()));
        }

        BootstrappingKey { bk, n, params }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tgsw_decompose() {
        let params = TgswParams::default();
        let value = Torus::new(0.123456);
        let decomposed = TgswSample::decompose(&value, &params);

        assert_eq!(decomposed.len(), params.l);

        let half_bg = (1i32 << params.bg_bit) / 2;
        for digit in &decomposed {
            assert!(*digit >= -half_bg && *digit < half_bg);
        }
    }

    #[test]
    fn test_tgsw_cmux() {
        let tlwe_params = TlweParams {
            n: 10,
            stddev: 1e-9,
        };

        let tgsw_params = TgswParams {
            l: 2,
            bg_bit: 8,
            tlwe_params: tlwe_params.clone(),
        };

        let sk = TlweSecretKey::generate_binary(tlwe_params.clone());

        let m0 = Torus::new(0.1);
        let m1 = Torus::new(0.7);
        let c0 = TlweSample::encrypt(&m0, &sk);
        let c1 = TlweSample::encrypt(&m1, &sk);

        let selector = TgswSample::encrypt(1, &sk, tgsw_params.clone());

        let result = selector.cmux(&c0, &c1);
        let decrypted = result.decrypt_phase(&sk);

        assert!((decrypted.value() - 0.7).abs() < 0.01);

        let selector0 = TgswSample::encrypt(0, &sk, tgsw_params);
        let result0 = selector0.cmux(&c0, &c1);
        let decrypted0 = result0.decrypt_phase(&sk);

        assert!((decrypted0.value() - 0.1).abs() < 0.01);
    }
}