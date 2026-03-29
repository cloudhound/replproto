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

// CompressBlock compresses a block using S2.
// returns nil if the block is all zeros (zero-block optimization).
// S2 handles zero runs efficiently so no separate sparse pass is needed.
// falls back to raw storage if S2 expands the data.
//
// designed for minimal CPU impact: one zero-check pass (uint64),
// then a single S2 pass. no intermediate copies.
func CompressBlock(data []byte) ([]byte, error) {
	if IsZeroBlock(data) {
		return nil, nil
	}

	// single allocation: tag byte + max compressed output.
	// S2 writes directly into this buffer — no pool, no copy.
	maxLen := s2.MaxEncodedLen(len(data))
	if maxLen <= 0 {
		out := make([]byte, 1+len(data))
		out[0] = EncodingRaw
		copy(out[1:], data)
		return out, nil
	}

	buf := make([]byte, 1+maxLen)
	buf[0] = EncodingS2
	compressed := s2.Encode(buf[1:], data)

	if len(compressed) >= len(data) {
		// S2 expanded the data (encrypted/already-compressed) — store raw
		out := make([]byte, 1+len(data))
		out[0] = EncodingRaw
		copy(out[1:], data)
		return out, nil
	}

	return buf[:1+len(compressed)], nil
}

// MaxDecompressedSize is the maximum allowed decompressed block size (16 MiB)
const MaxDecompressedSize = 16 << 20

// DecompressBlock decompresses a block by reading the encoding tag prefix
// and dispatching to the appropriate decoder.
func DecompressBlock(compressed []byte, uncompressedLen int) ([]byte, error) {
	if uncompressedLen <= 0 || uncompressedLen > MaxDecompressedSize {
		return nil, fmt.Errorf("invalid uncompressed length: %d (max %d)", uncompressedLen, MaxDecompressedSize)
	}

	if len(compressed) < 1 {
		return nil, fmt.Errorf("empty compressed data")
	}

	switch compressed[0] {
	case EncodingS2:
		return s2.Decode(nil, compressed[1:])

	case EncodingRaw:
		buf := make([]byte, uncompressedLen)
		copy(buf, compressed[1:])
		return buf, nil

	default:
		return nil, fmt.Errorf("unknown encoding tag: 0x%02X", compressed[0])
	}
}

// IsZeroBlock checks if all bytes in the block are zero.
// Uses uint64 comparisons for speed (~8x faster than byte-at-a-time).
func IsZeroBlock(data []byte) bool {
	n := len(data)
	i := 0
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
