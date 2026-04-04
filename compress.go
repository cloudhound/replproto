package replproto

import (
	"encoding/binary"
	"fmt"

	"github.com/klauspost/compress/s2"
)

// encoding tag prefixes - first byte of every compressed payload
const (
	EncodingS2  byte = 0x05
	EncodingRaw byte = 0x04
)

// CompressBlock compresses src into dst using S2 and computes the XXH64
// checksum in a single pass over src. dst is reused if large enough.
// if checksum is non-zero it is used as-is (caller already computed it).
// returns (nil, zero-checksum, nil) if the block is all zeros — both
// hashing and compression are skipped entirely for zero blocks.
func CompressBlock(dst, src []byte, checksum ...[ChecksumSize]byte) ([]byte, [ChecksumSize]byte, error) {
	var cs [ChecksumSize]byte

	if IsZeroBlock(src) {
		return dst[:0], cs, nil
	}

	if len(checksum) > 0 {
		cs = checksum[0]
	}

	// compute checksum if not provided
	var zero [ChecksumSize]byte
	if cs == zero {
		binary.BigEndian.PutUint64(cs[:], xxh64Sum(src))
	}

	maxLen := s2.MaxEncodedLen(len(src))
	if maxLen <= 0 {
		// too large for S2 - store raw
		needed := 1 + len(src)
		dst = grow(dst, needed)
		dst[0] = EncodingRaw
		copy(dst[1:], src)
		return dst[:needed], cs, nil
	}

	needed := 1 + maxLen
	dst = grow(dst, needed)
	dst[0] = EncodingS2
	compressed := s2.Encode(dst[1:], src)

	if len(compressed) >= len(src) {
		// S2 expanded the data - store raw
		dst[0] = EncodingRaw
		copy(dst[1:], src)
		return dst[:1+len(src)], cs, nil
	}

	return dst[:1+len(compressed)], cs, nil
}

// DecompressBlock decompresses src into dst and optionally verifies the
// checksum. pass a zero checksum to skip verification.
// dst is reused if large enough. The returned slice may alias dst.
func DecompressBlock(dst, src []byte, uncompressedLen int, checksum [ChecksumSize]byte) ([]byte, error) {
	if uncompressedLen <= 0 || uncompressedLen > MaxDecompressedSize {
		return nil, fmt.Errorf("invalid uncompressed length: %d (max %d)", uncompressedLen, MaxDecompressedSize)
	}

	// zero block: empty compressed payload → fill with zeros
	if len(src) == 0 {
		// verify the checksum is also zero - a non-zero checksum with empty
		// payload means the original block was not zero and corruption occurred
		var zero [ChecksumSize]byte
		if checksum != zero {
			return nil, fmt.Errorf("checksum mismatch: non-zero checksum on zero block")
		}
		dst = grow(dst, uncompressedLen)
		memset(dst[:uncompressedLen], 0)
		return dst[:uncompressedLen], nil
	}

	var out []byte
	var err error

	switch src[0] {
	case EncodingS2:
		dst = grow(dst, uncompressedLen)
		out, err = s2.Decode(dst[:uncompressedLen], src[1:])
		if err != nil {
			return nil, err
		}

	case EncodingRaw:
		if len(src)-1 != uncompressedLen {
			return nil, fmt.Errorf("raw block size mismatch: payload %d, expected %d", len(src)-1, uncompressedLen)
		}
		dst = grow(dst, uncompressedLen)
		copy(dst, src[1:])
		out = dst[:uncompressedLen]

	default:
		return nil, fmt.Errorf("unknown encoding tag: 0x%02X", src[0])
	}

	// verify checksum if non-zero
	var zero [ChecksumSize]byte
	if checksum != zero {
		var actual [ChecksumSize]byte
		binary.BigEndian.PutUint64(actual[:], xxh64Sum(out))
		if actual != checksum {
			return nil, fmt.Errorf("checksum mismatch")
		}
	}

	return out, nil
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
