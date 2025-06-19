#[derive(Debug, Clone, Copy)]
pub struct Torus(f64);

impl Torus {
    pub fn new(value: f64) -> Self {
        let wrapped = value - value.floor();
        Torus(wrapped)
    }

    pub fn value(&self) -> f64 {
        self.0        
    }

    pub fn add(&self, other: &Torus) -> Self {
        Torus::new(self.0 + other.0)
    }

    pub fn sub(&self, other: &Torus) -> Self {
        Torus::new(self.0 - other.0)
    }

    pub fn mul_scalar(&self, scalar: f64) -> Self {
        Torus::new(self.0 * scalar)
    }

    pub fn round(&self, precision: u32) -> Torus {
        let divisor = 2.0_f64.powi(precision as i32);
        let rounded = (self.0 * divisor).round() / divisor;
        Torus::new(rounded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_torus_wrapping() {
        let t1 = Torus::new(1.5);
        assert!((t1.value() - 0.5).abs() < 1e-10);

        let t2 = Torus::new(-0.3);
        assert!((t2.value() - 0.7).abs() < 1e-10);
    }
    
    #[test]
    fn test_torus_addition() {
        let t1 = Torus::new(0.7);
        let t2 = Torus::new(0.5);
        let result = t1.add(&t2);

        assert!((result.value() - 0.2).abs() < 1e-10);
    }
    
    #[test]
    fn test_torus_subtraction() {
        let t1 = Torus::new(0.3);
        let t2 = Torus::new(0.5);
        let result = t1.sub(&t2);

        assert!((result.value() - 0.8).abs() < 1e-10);
    }
}