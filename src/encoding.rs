use crate::torus::Torus;

pub fn encode_bit(bit: bool) -> Torus {
    if bit {
        Torus::new(0.25) // 1/4 for some noise
    } else {
        Torus::new(0.0)
    }
}

pub fn decode_bit(t: &Torus) -> bool {
    let val = t.value();
    let dist_to_0 = val.min(1.0 - val);
    let diff = (val - 0.25).abs();
    let dist_to_025 = diff.min(1.0 - diff);

    dist_to_025 < dist_to_0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode() {
        let zero = encode_bit(false);
        let one = encode_bit(true);

        assert_eq!(decode_bit(&zero), false);
        assert_eq!(decode_bit(&one), true);
    }

    #[test]
    fn test_decode_with_noise() {
        // Even with small noise, decoding should work
        let noisy_zero = Torus::new(0.05); // Close to 0
        let noisy_one = Torus::new(0.23); // Close to 0.25

        assert_eq!(decode_bit(&noisy_zero), false);
        assert_eq!(decode_bit(&noisy_one), true);
    }
}
