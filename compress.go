package replproto

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"fmt"
	"io"
	"sync"
)

// compressorPool reuses flate writers to avoid allocating a new compressor
// for every 1 MiB block across 32 workers.
var compressorPool = sync.Pool{
	New: func() any {
		w, _ := flate.NewWriter(nil, flate.BestSpeed)
		return w
	},
}

// CompressBlock compresses a block using flate level 1 (fastest).
// returns nil if the block is all zeros (zero-block optimization).
func CompressBlock(data []byte) ([]byte, error) {
	if IsZeroBlock(data) {
		return nil, nil // zero block - no data to send
	}

	var buf bytes.Buffer
	w := compressorPool.Get().(*flate.Writer)
	w.Reset(&buf)

	if _, err := w.Write(data); err != nil {
		compressorPool.Put(w)
		return nil, fmt.Errorf("compress: %w", err)
	}

	if err := w.Close(); err != nil {
		compressorPool.Put(w)
		return nil, fmt.Errorf("close compressor: %w", err)
	}

	compressorPool.Put(w)
	return buf.Bytes(), nil
}

// MaxDecompressedSize is the maximum allowed decompressed block size (16 MiB)
const MaxDecompressedSize = 16 << 20

// sparse encoding constants - must match agent/replication/sparse.go
const sparseMarker = uint32(0x53505253) // "SPRS"

// DecompressBlock decompresses a block that was encoded with either flate
// compression or sparse encoding.
func DecompressBlock(compressed []byte, uncompressedLen int) ([]byte, error) {
	if uncompressedLen <= 0 || uncompressedLen > MaxDecompressedSize {
		return nil, fmt.Errorf("invalid uncompressed length: %d (max %d)", uncompressedLen, MaxDecompressedSize)
	}

	// check for sparse encoding
	if isSparseEncoded(compressed) {
		return decodeSparse(compressed, uncompressedLen)
	}

	// standard flate decompression
	r := flate.NewReader(bytes.NewReader(compressed))
	defer r.Close()

	buf := make([]byte, uncompressedLen)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, fmt.Errorf("decompress: %w", err)
	}

	return buf, nil
}

// isSparseEncoded checks if a payload is sparse-encoded by checking the marker
func isSparseEncoded(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	return binary.BigEndian.Uint32(data[0:4]) == sparseMarker
}

// decodeSparse decodes a sparse-encoded payload back into a full block.
// the caller provides the expected uncompressed length.
func decodeSparse(encoded []byte, uncompressedLen int) ([]byte, error) {
	block := make([]byte, uncompressedLen) // zero-filled

	if len(encoded) < 6 {
		return block, nil
	}

	regionCount := binary.BigEndian.Uint16(encoded[4:6])
	pos := 6

	for i := uint16(0); i < regionCount; i++ {
		if pos+8 > len(encoded) {
			break
		}
		offset := binary.BigEndian.Uint32(encoded[pos : pos+4])
		length := binary.BigEndian.Uint32(encoded[pos+4 : pos+8])
		pos += 8

		if pos+int(length) > len(encoded) {
			break
		}
		if int(offset)+int(length) <= uncompressedLen {
			copy(block[offset:offset+length], encoded[pos:pos+int(length)])
		}
		pos += int(length)
	}

	return block, nil
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
