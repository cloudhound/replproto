package replproto

import (
	"bytes"
	"compress/flate"
	"fmt"
	"io"
	"sync"
	"unsafe"

	"github.com/pierrec/lz4/v4"
)

// encoding tag prefixes - first byte of every compressed payload
const (
	EncodingFlate  byte = 0x01
	EncodingSparse byte = 0x02
	EncodingLZ4    byte = 0x03
	EncodingRaw    byte = 0x04
)

// lz4BufPool reuses LZ4 output buffers to avoid per-call allocation.
var lz4BufPool = sync.Pool{
	New: func() any {
		buf := make([]byte, 0, 4096)
		return &buf
	},
}

// flateWriterPool reuses flate.Writer to avoid rebuilding Huffman state.
var flateWriterPool = sync.Pool{
	New: func() any {
		w, _ := flate.NewWriter(nil, flate.BestSpeed)
		return w
	},
}

// CompressBlock compresses a block using LZ4.
// returns nil if the block is all zeros (zero-block optimization).
// for blocks with large zero regions (sparse), uses sparse encoding which
// skips zero runs entirely. falls back to raw storage if LZ4 can't compress,
// since incompressible data won't benefit from flate either.
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

	// lz4 block compression with pooled output buffer
	maxLen := lz4.CompressBlockBound(len(data))
	bufp := lz4BufPool.Get().(*[]byte)
	buf := *bufp
	needed := 1 + maxLen
	if cap(buf) < needed {
		buf = make([]byte, needed)
	} else {
		buf = buf[:needed]
	}
	buf[0] = EncodingLZ4

	n, err := lz4.CompressBlock(data, buf[1:], nil)
	if err == nil && n > 0 {
		out := make([]byte, 1+n)
		copy(out, buf[:1+n])
		*bufp = buf
		lz4BufPool.Put(bufp)
		return out, nil
	}

	*bufp = buf
	lz4BufPool.Put(bufp)

	// LZ4 couldn't compress — store raw. Incompressible data won't benefit
	// from flate either, and flate burns significant CPU rebuilding state.
	out := make([]byte, 1+len(data))
	out[0] = EncodingRaw
	copy(out[1:], data)
	return out, nil
}

// flateCompress compresses data using flate level 1 (fastest).
// the output is prefixed with EncodingFlate tag byte.
func flateCompress(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte(EncodingFlate)

	w := flateWriterPool.Get().(*flate.Writer)
	w.Reset(&buf)

	if _, err := w.Write(data); err != nil {
		flateWriterPool.Put(w)
		return nil, fmt.Errorf("compress: %w", err)
	}

	if err := w.Close(); err != nil {
		flateWriterPool.Put(w)
		return nil, fmt.Errorf("close compressor: %w", err)
	}

	flateWriterPool.Put(w)
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
	// check 8 bytes at a time via uint64
	i := 0
	for i+8 <= n {
		if *(*uint64)(unsafe.Pointer(&data[i])) != 0 {
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
