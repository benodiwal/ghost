use rand::rng;
use rand_distr::{Distribution, Normal};

/// Generate Gaussian noise with given standard deviation
pub fn gaussian_noise(stddev: f64) -> f64 {
    let normal = Normal::new(0.0, stddev).unwrap();
    let mut rng = rng();
    normal.sample(&mut rng)
}

/// Generate a vector of Gaussian noise values
pub fn gaussian_noise_vec(len: usize, stddev: f64) -> Vec<f64> {
    (0..len).map(|_| gaussian_noise(stddev)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_gaussian_noise_distribution() {
        // Generate lots of samples
        let samples: Vec<f64> = (0..10000)
            .map(|_| gaussian_noise(1.0))
            .collect();
        
        // Mean should be close to 0
        let mean: f64 = samples.iter().sum::<f64>() / samples.len() as f64;
        assert!(mean.abs() < 0.1);
        
        // Most values should be within 3 standard deviations
        let within_3std = samples.iter()
            .filter(|&&x| x.abs() < 3.0)
            .count();
        assert!(within_3std as f64 / samples.len() as f64 > 0.99);
    }
}