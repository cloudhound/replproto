//go:build amd64

package replproto

var hasAVX2 bool

func init() {
	hasAVX2 = cpuidHasAVX2()
}

// Assembly declarations — implementations in zero_amd64.s
func cpuidHasAVX2() bool
func isZeroAVX2(data []byte) bool

// IsZeroBlock checks if all bytes in the block are zero.
// Uses AVX2 SIMD when available (256 bits per cycle, 128 bytes per
// unrolled iteration), falling back to uint64 unrolling otherwise.
func IsZeroBlock(data []byte) bool {
	if hasAVX2 && len(data) >= 32 {
		return isZeroAVX2(data)
	}
	return isZeroBlockGeneric(data)
}
