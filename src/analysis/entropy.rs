//! Shannon entropy in bits per byte (0..8).

pub fn entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u64; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let n = data.len() as f64;
    let mut h = 0.0;
    for &f in &freq {
        if f == 0 {
            continue;
        }
        let p = f as f64 / n;
        h -= p * p.log2();
    }
    h
}

/// A coarse entropy map: `buckets` samples across the whole file, each the mean
/// entropy of its slice. Used for the `map` command to spot packed regions.
pub fn entropy_map(data: &[u8], buckets: usize) -> Vec<f64> {
    if data.is_empty() || buckets == 0 {
        return Vec::new();
    }
    let step = data.len().div_ceil(buckets);
    data.chunks(step).map(entropy).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zeros_have_no_entropy() {
        assert_eq!(entropy(&[0u8; 1024]), 0.0);
    }

    #[test]
    fn uniform_bytes_are_max_entropy() {
        let data: Vec<u8> = (0..=255).cycle().take(4096).collect();
        assert!((entropy(&data) - 8.0).abs() < 1e-6);
    }

    #[test]
    fn empty_is_zero() {
        assert_eq!(entropy(&[]), 0.0);
        assert!(entropy_map(&[], 8).is_empty());
    }

    #[test]
    fn map_has_requested_resolution() {
        let data = vec![0u8; 800];
        let m = entropy_map(&data, 8);
        assert_eq!(m.len(), 8);
    }
}
