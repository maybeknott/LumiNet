package crypto

import (
	"testing"
)

func TestBlackRockSymmetry(t *testing.T) {
	ranges := []uint64{10, 100, 500}
	seeds := []uint64{1, 42, 999999}
	rounds := []uint32{4, 6}

	for _, rangeVal := range ranges {
		for _, seed := range seeds {
			for _, r := range rounds {
				br := NewBlackRock(rangeVal, seed, r)

				// Track seen shuffled values to ensure bijection (uniqueness)
				seen := make(map[uint64]bool)

				for i := uint64(0); i < rangeVal; i++ {
					shuffled := br.Shuffle(i)
					if shuffled >= rangeVal {
						t.Errorf("shuffled value %d >= range %d for seed %d, rounds %d", shuffled, rangeVal, seed, r)
					}

					if seen[shuffled] {
						t.Errorf("collision detected: shuffled value %d seen twice for range %d, seed %d, rounds %d", shuffled, rangeVal, seed, r)
					}
					seen[shuffled] = true

					unshuffled := br.Unshuffle(shuffled)
					if unshuffled != i {
						t.Errorf("symmetry failed: expected %d, got %d for range %d, seed %d, rounds %d", i, unshuffled, rangeVal, seed, r)
					}
				}
			}
		}
	}
}
