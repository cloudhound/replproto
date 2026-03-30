//go:build !amd64

package replproto

// IsZeroBlock checks if all bytes in the block are zero.
// Uses unrolled uint64 comparisons for speed.
func IsZeroBlock(data []byte) bool {
	return isZeroBlockGeneric(data)
}
