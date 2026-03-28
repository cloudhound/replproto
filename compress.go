package replproto

import (
	"bytes"
	"compress/flate"
	"fmt"
	"io"
	"sync"
)

// encoding tag prefixes - first byte of every compressed payload
const (
	encodingFlate  byte = 0x01
	encodingSparse byte = 0x02
)

// compressorPool reuses flate writers to avoid allocating a new compressor
// for every 1 MiB block across 32 workers.
var compressorPool = sync.Pool{
	New: func() any {
		w, _ := flate.NewWriter(nil, flate.BestSpeed)
		return w
	},
}

// CompressBlock compresses a block using the best available method.
// returns nil if the block is all zeros (zero-block optimization).
// for blocks with large zero regions (sparse), uses sparse encoding which
// skips zero runs entirely. otherwise uses flate level 1 compression.
// the first byte of the returned slice is an encoding tag so the decoder
// knows which format was used without magic-byte sniffing.
func CompressBlock(data []byte) ([]byte, error) {
	if IsZeroBlock(data) {
		return nil, nil // zero block - no data to send
	}

	// try sparse encoding first - beneficial for VM disks, database files,
	// and NTFS sparse files where allocated blocks contain large zero regions
	if sparse := trySparseEncode(data); sparse != nil {
		// compare sparse size with flate to pick the smaller one
		flateData, err := flateCompress(data)
		if err != nil {
			return sparse, nil // flate failed, use sparse
		}
		if len(sparse) < len(flateData) {
			return sparse, nil
		}
		return flateData, nil
	}

	return flateCompress(data)
}

// flateCompress compresses data using flate level 1 (fastest).
// the output is prefixed with encodingFlate tag byte.
func flateCompress(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte(encodingFlate)

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
	case encodingSparse:
		return decodeSparse(compressed[1:], uncompressedLen)

	case encodingFlate:
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
