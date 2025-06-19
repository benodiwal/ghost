use rand::Rng;
use crate::noise::gaussian_noise;

#[derive(Debug, Clone)]
pub struct LweParams {
    pub n: usize,
    pub q: u64,
    pub stddev: f64,
}

impl Default for LweParams {
    fn default() -> Self {
        LweParams {
            n: 630,
            q: 1 << 32,
            stddev: 3.2,
        }
    }
}

#[derive(Debug, Clone)]
pub struct LweSecretKey {
    pub coeffs: Vec<i32>,
    pub params: LweParams,
}

impl LweSecretKey {
    pub fn generate_binary(params: LweParams) -> Self {
        let mut rng = rand::rng();
        let coeffs: Vec<i32> = (0..params.n)
            .map(|_| if rng.random_bool(0.5) { 1 } else { 0 })
            .collect();

        LweSecretKey { coeffs, params }
    }

    pub fn generate_ternary(params: LweParams) -> Self {
        let mut rng = rand::rng();
        let coeffs: Vec<i32> = (0..params.n)
            .map(|_| {
                let r: f64 = rng.random();
                if r < 0.333 { -1 }
                else if r < 0.667 { 0 }
                else { 1 }
            })
            .collect();

        LweSecretKey { coeffs, params }
    }
}

#[derive(Debug, Clone)]
pub struct LweCiphertext {
    pub a: Vec<u64>,
    pub b: u64,
    pub params: LweParams,
}

impl LweCiphertext {
    pub fn encrypt(message: u64, sk: &LweSecretKey) -> Self {
        let mut rng = rand::rng();

        let a: Vec<u64> = (0..sk.params.n)
            .map(|_| rng.random::<u64>() % sk.params.q)
            .collect();

        let mut inner_product: i64 = 0;
        for i in 0..sk.params.n {
            inner_product += (a[i] as i64) * (sk.coeffs[i] as i64);
            inner_product %= sk.params.q as i64;
        }

        let error = gaussian_noise(sk.params.stddev) as i64;
        let b = ((inner_product + message as i64 + error) % sk.params.q as i64) as u64;

        LweCiphertext {
            a,
            b,
            params: sk.params.clone(),
        }
    }

    pub fn decrypt(&self, sk: &LweSecretKey) -> u64 {
        let mut inner_product: i64 = 0;
        for i in 0..sk.params.n {
            inner_product += (self.a[i] as i64) * (sk.coeffs[i] as i64);
            inner_product %= self.params.q as i64;
        }

        let mut message = (self.b as i64 - inner_product) % self.params.q as i64;
        if message < 0 {
            message += self.params.q as i64;
        }

        message as u64
    }

    pub fn add(&self, other: &LweCiphertext) -> LweCiphertext {
        assert_eq!(self.params.n, other.params.n);
        assert_eq!(self.params.q, other.params.q);

        let a: Vec<u64> = self.a.iter()
            .zip(other.a.iter())
            .map(|(x, y)| (x + y) % self.params.q)
            .collect();

        let b = (self.b + other.b) % self.params.q;

        LweCiphertext {
            a,
            b,
            params: self.params.clone(),
        }
    }

    pub fn scalar_mul(&self, scalar: u64) -> LweCiphertext {
        let a: Vec<u64> = self.a.iter()
            .map(|x| (x * scalar) % self.params.q)
            .collect();

        let b = (self.b * scalar) % self.params.q;

        LweCiphertext {
            a,
            b,
            params: self.params.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lwe_encrypt_decrypt() {
        let params = LweParams {
            n: 10,
            q: 1024,
            stddev: 1.0,
        };

        let sk = LweSecretKey::generate_binary(params.clone());
        let message = 42;
        let ct = LweCiphertext::encrypt(message, &sk);
        let decrypted = ct.decrypt(&sk);

        assert!((decrypted as i64 - message as i64).abs() < 10);
    }

    #[test]
    fn test_homomorphic_addition() {
        let params = LweParams {
            n: 10,
            q: 1024,
            stddev: 0.5,
        };

        let sk = LweSecretKey::generate_binary(params.clone());

        let m1 = 10;
        let m2 = 20;
        let ct1 = LweCiphertext::encrypt(m1, &sk);
        let ct2 = LweCiphertext::encrypt(m2, &sk);

        let ct_sum = ct1.add(&ct2);
        let decrypted = ct_sum.decrypt(&sk);

        assert!((decrypted as i64 - (m1 + m2) as i64).abs() < 10);
    }
}