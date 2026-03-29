package replproto

import (
	"fmt"
	"unsafe"

	"github.com/klauspost/compress/s2"
)

// encoding tag prefixes - first byte of every compressed payload
const (
	EncodingS2  byte = 0x05
	EncodingRaw byte = 0x04
)

// CompressBlock compresses src into dst using S2.
// dst is reused if large enough, grown if not. The returned slice may
// alias dst's underlying array — the caller should keep one dst buffer
// and pass it to every call for zero-GC operation.
//
// returns (nil, nil) if the block is all zeros.
func CompressBlock(dst, src []byte) ([]byte, error) {
	if IsZeroBlock(src) {
		return dst[:0], nil
	}

	maxLen := s2.MaxEncodedLen(len(src))
	if maxLen <= 0 {
		// too large for S2 — store raw
		needed := 1 + len(src)
		dst = grow(dst, needed)
		dst[0] = EncodingRaw
		copy(dst[1:], src)
		return dst[:needed], nil
	}

	needed := 1 + maxLen
	dst = grow(dst, needed)
	dst[0] = EncodingS2
	compressed := s2.Encode(dst[1:], src)

	if len(compressed) >= len(src) {
		// S2 expanded the data — store raw
		needed = 1 + len(src)
		dst = grow(dst, needed)
		dst[0] = EncodingRaw
		copy(dst[1:], src)
		return dst[:needed], nil
	}

	return dst[:1+len(compressed)], nil
}

// DecompressBlock decompresses src into dst.
// dst is reused if large enough. The returned slice may alias dst.
func DecompressBlock(dst, src []byte, uncompressedLen int) ([]byte, error) {
	if uncompressedLen <= 0 || uncompressedLen > MaxDecompressedSize {
		return nil, fmt.Errorf("invalid uncompressed length: %d (max %d)", uncompressedLen, MaxDecompressedSize)
	}

	if len(src) < 1 {
		return nil, fmt.Errorf("empty compressed data")
	}

	switch src[0] {
	case EncodingS2:
		dst = grow(dst, uncompressedLen)
		return s2.Decode(dst[:uncompressedLen], src[1:])

	case EncodingRaw:
		dst = grow(dst, uncompressedLen)
		copy(dst, src[1:])
		return dst[:uncompressedLen], nil

	default:
		return nil, fmt.Errorf("unknown encoding tag: 0x%02X", src[0])
	}
}

// MaxDecompressedSize is the maximum allowed decompressed block size (16 MiB)
const MaxDecompressedSize = 16 << 20

// grow returns a slice with at least n bytes of capacity.
// reuses the existing backing array if possible.
func grow(buf []byte, n int) []byte {
	if cap(buf) >= n {
		return buf[:n]
	}
	return make([]byte, n)
}

// IsZeroBlock checks if all bytes in the block are zero.
// Uses unrolled uint64 comparisons for speed.
func IsZeroBlock(data []byte) bool {
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
