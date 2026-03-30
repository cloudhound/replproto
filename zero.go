package replproto

import "unsafe"

// isZeroBlockGeneric checks if all bytes in the block are zero.
// Uses unrolled uint64 comparisons for speed on non-SIMD paths.
func isZeroBlockGeneric(data []byte) bool {
	n := len(data)
	i := 0
	// process 32 bytes per iteration (4 × uint64)
	for i+32 <= n {
		w0 := *(*uint64)(unsafe.Pointer(&data[i]))
		w1 := *(*uint64)(unsafe.Pointer(&data[i+8]))
		w2 := *(*uint64)(unsafe.Pointer(&data[i+16]))
		w3 := *(*uint64)(unsafe.Pointer(&data[i+24]))
		if (w0 | w1 | w2 | w3) != 0 {
			return false
		}
		i += 32
	}
	for i+8 <= n {
		if *(*uint64)(unsafe.Pointer(&data[i])) != 0 {
			return false
		}
		i += 8
	}
	for ; i < n; i++ {
		if data[i] != 0 {
			return false
		}
	}
	return true
}

// Pre-filled pages for efficient memset via copy().
// copy() uses the runtime's optimized memmove, which is reliably
// faster than a compiler-dependent for-range fill loop.
var (
	zeroPage [4096]byte
	onesPage [4096]byte
)

func init() {
	for i := range onesPage {
		onesPage[i] = 0xFF
	}
}

// memset fills dst with val using page-sized copy() calls.
// Only 0x00 and 0xFF are used in practice (bitmap decode).
func memset(dst []byte, val byte) {
	var page *[4096]byte
	if val == 0 {
		page = &zeroPage
	} else {
		page = &onesPage
	}
	for len(dst) > 0 {
		n := copy(dst, page[:])
		dst = dst[n:]
	}
}
