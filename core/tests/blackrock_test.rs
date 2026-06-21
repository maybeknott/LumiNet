//! # Blackrock Cipher Tests
//!
//! Verification tests for the Blackrock Generalized Feistel Cipher.

use lumicore::cidr::BlackRock;
use std::collections::HashSet;

#[test]
fn test_blackrock_uniqueness_and_reversibility() {
    let range = 1000;
    let seed = 12345;
    let rounds = 4;
    let br = BlackRock::new(range, seed, rounds);

    let mut shuffled_set = HashSet::new();

    for i in 0..range {
        let shuffled = br.shuffle(i);
        assert!(shuffled < range, "Shuffled value {} must be within range {}", shuffled, range);
        
        let unshuffled = br.unshuffle(shuffled);
        assert_eq!(unshuffled, i, "Unshuffle({}) must equal original {}", shuffled, i);

        shuffled_set.insert(shuffled);
    }

    assert_eq!(shuffled_set.len(), range as usize, "All shuffled values must be unique");
}

#[test]
fn test_blackrock_determinism() {
    let range = 10000;
    let seed = 987654321;
    let rounds = 6;
    
    let br1 = BlackRock::new(range, seed, rounds);
    let br2 = BlackRock::new(range, seed, rounds);

    for i in 0..100 {
        assert_eq!(br1.shuffle(i), br2.shuffle(i), "Shuffling must be deterministic");
        assert_eq!(br1.unshuffle(i), br2.unshuffle(i), "Unshuffling must be deterministic");
    }
}
