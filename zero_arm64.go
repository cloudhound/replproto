//go:build arm64

package replproto

// assembly declaration — implementation in zero_arm64.s
func isZeroNEON(data []byte) bool

// IsZeroBlock checks if all bytes in the block are zero.
// uses NEON SIMD when data is at least 16 bytes (128 bits per register,
// 64 bytes per unrolled iteration), falling back to uint64 unrolling
// for smaller blocks.
func IsZeroBlock(data []byte) bool {
	if len(data) >= 16 {
		return isZeroNEON(data)
	}
	return isZeroBlockGeneric(data)
}
