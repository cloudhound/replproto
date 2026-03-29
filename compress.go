package replproto

import (
	"bytes"
	"compress/flate"
	"fmt"
	"io"

	"github.com/pierrec/lz4/v4"
)

// encoding tag prefixes - first byte of every compressed payload
const (
	EncodingFlate  byte = 0x01
	EncodingSparse byte = 0x02
	EncodingLZ4    byte = 0x03
)

// CompressBlock compresses a block using LZ4.
// returns nil if the block is all zeros (zero-block optimization).
// for blocks with large zero regions (sparse), uses sparse encoding which
// skips zero runs entirely. falls back to flate if LZ4 can't compress.
// the first byte of the returned slice is an encoding tag so the decoder
// knows which format was used.
func CompressBlock(data []byte) ([]byte, error) {
	if IsZeroBlock(data) {
		return nil, nil
	}

	// try sparse encoding first - beneficial for VM disks, database files,
	// and NTFS sparse files where allocated blocks contain large zero regions
	if sparse := trySparseEncode(data); sparse != nil {
		return sparse, nil
	}

	// lz4 block compression
	maxLen := lz4.CompressBlockBound(len(data))
	buf := make([]byte, 1+maxLen)
	buf[0] = EncodingLZ4
	n, err := lz4.CompressBlock(data, buf[1:], nil)
	if err == nil && n > 0 {
		return buf[:1+n], nil
	}

	// lz4 couldn't compress (incompressible data), fall back to flate
	return flateCompress(data)
}

// flateCompress compresses data using flate level 1 (fastest).
// the output is prefixed with EncodingFlate tag byte.
func flateCompress(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte(EncodingFlate)

	w, _ := flate.NewWriter(&buf, flate.BestSpeed)

	if _, err := w.Write(data); err != nil {
		return nil, fmt.Errorf("compress: %w", err)
	}

	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("close compressor: %w", err)
	}

	return buf.Bytes(), nil
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
	case EncodingSparse:
		return decodeSparse(compressed[1:], uncompressedLen)

	case EncodingLZ4:
		buf := make([]byte, uncompressedLen)
		n, err := lz4.UncompressBlock(compressed[1:], buf)
		if err != nil {
			return nil, fmt.Errorf("lz4 decompress: %w", err)
		}
		return buf[:n], nil

	case EncodingFlate:
		r := flate.NewReader(bytes.NewReader(compressed[1:]))
		defer r.Close()

		buf := make([]byte, uncompressedLen)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, fmt.Errorf("decompress: %w", err)
		}

		return buf, nil

	default:
		return nil, fmt.Errorf("unknown encoding tag: 0x%02X", compressed[0])
	}
}

// IsZeroBlock checks if all bytes in the block are zero
func IsZeroBlock(data []byte) bool {
	// check in 8-byte chunks for speed
	n := len(data)
	i := 0

	// check 8 bytes at a time
	for i+8 <= n {
		if data[i] != 0 || data[i+1] != 0 || data[i+2] != 0 || data[i+3] != 0 ||
			data[i+4] != 0 || data[i+5] != 0 || data[i+6] != 0 || data[i+7] != 0 {
			return false
		}
		i += 8
	}

	// check remaining bytes
	for ; i < n; i++ {
		if data[i] != 0 {
			return false
		}
	}

	return true
}
