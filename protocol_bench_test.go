package replproto

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"
)

func BenchmarkEncodeFrame(b *testing.B) {
	enc := &FrameEncoder{}
	payload := make([]byte, 4096)
	rand.Read(payload)
	f := Frame{Type: MsgBlockData, Payload: payload}
	var buf bytes.Buffer

	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf.Reset()
		enc.EncodeFrame(&buf, f)
	}
}

func BenchmarkDecodeFrame(b *testing.B) {
	enc := &FrameEncoder{}
	payload := make([]byte, 4096)
	rand.Read(payload)
	f := Frame{Type: MsgBlockData, Payload: payload}
	var buf bytes.Buffer
	enc.EncodeFrame(&buf, f)
	frameBytes := buf.Bytes()

	dec := &FrameDecoder{}
	b.SetBytes(int64(len(frameBytes)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dec.DecodeFrame(bytes.NewReader(frameBytes))
	}
}

func BenchmarkCompressBlock(b *testing.B) {
	src := make([]byte, 4096)
	rand.Read(src)
	var dst []byte

	b.SetBytes(int64(len(src)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dst, _ = CompressBlock(dst, src)
	}
}

func BenchmarkCompressBlockZero(b *testing.B) {
	src := make([]byte, 4096)
	var dst []byte

	b.SetBytes(int64(len(src)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dst, _ = CompressBlock(dst, src)
	}
}

func BenchmarkDecompressBlock(b *testing.B) {
	src := make([]byte, 4096)
	rand.Read(src)
	compressed, _ := CompressBlock(nil, src)
	var dst []byte

	b.SetBytes(int64(len(src)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dst, _ = DecompressBlock(dst, compressed, len(src))
	}
}

func BenchmarkIsZeroBlock(b *testing.B) {
	data := make([]byte, 4096)
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		IsZeroBlock(data)
	}
}

func BenchmarkEncodeBitmapRLE_Sparse(b *testing.B) {
	// 1 MiB bitmap (~8M blocks), mostly zeros with occasional set bits
	totalBlocks := uint64(8 * 1024 * 1024)
	bitmap := make([]byte, totalBlocks/8)
	// set every 4096th bit
	for i := 0; i < len(bitmap); i += 512 {
		bitmap[i] = 0x80
	}
	var dst []byte

	b.SetBytes(int64(len(bitmap)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dst = AppendBitmapRLE(dst, bitmap, totalBlocks)
	}
}

func BenchmarkEncodeBitmapRLE_Dense(b *testing.B) {
	totalBlocks := uint64(8 * 1024 * 1024)
	bitmap := make([]byte, totalBlocks/8)
	for i := range bitmap {
		bitmap[i] = 0xFF
	}
	var dst []byte

	b.SetBytes(int64(len(bitmap)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dst = AppendBitmapRLE(dst, bitmap, totalBlocks)
	}
}

func BenchmarkEncodeBitmapRLE_Mixed(b *testing.B) {
	// 1 MiB bitmap with random data — exercises the CLZ slow path
	totalBlocks := uint64(8 * 1024 * 1024)
	bitmap := make([]byte, totalBlocks/8)
	rand.Read(bitmap)
	var dst []byte

	b.SetBytes(int64(len(bitmap)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dst = AppendBitmapRLE(dst, bitmap, totalBlocks)
	}
}

func BenchmarkDecodeBitmapRLE(b *testing.B) {
	totalBlocks := uint64(8 * 1024 * 1024)
	bitmap := make([]byte, totalBlocks/8)
	for i := range bitmap {
		bitmap[i] = 0xFF
	}
	encoded := EncodeBitmapRLE(bitmap, totalBlocks)
	var dst []byte

	b.SetBytes(int64(totalBlocks / 8))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dst, _ = DecodeBitmapRLETo(dst, encoded, totalBlocks)
	}
}

// BenchmarkEndToEnd measures the full replication pipeline:
// compress → encode block data payload → encode frame → decode frame → decompress
func BenchmarkEndToEnd(b *testing.B) {
	for _, size := range []int{4096, 64 * 1024, 256 * 1024, 1024 * 1024} {
		b.Run(fmt.Sprintf("size=%d", size), func(b *testing.B) {
			src := make([]byte, size)
			rand.Read(src)

			hdr := BlockDataHeader{
				DeviceID:        1,
				BlockOffset:     0,
				UncompressedLen: uint32(size),
			}

			enc := &FrameEncoder{}
			dec := &FrameDecoder{}
			var compBuf, payloadBuf, decompBuf []byte
			var buf bytes.Buffer

			b.SetBytes(int64(size))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				// --- sender side ---
				var err error
				compBuf, err = CompressBlock(compBuf, src)
				if err != nil {
					b.Fatal(err)
				}
				payloadBuf = EncodeBlockDataPayload(payloadBuf, hdr, compBuf)

				buf.Reset()
				if err := enc.EncodeFrame(&buf, Frame{Type: MsgBlockData, Payload: payloadBuf}); err != nil {
					b.Fatal(err)
				}

				// --- receiver side ---
				f, err := dec.DecodeFrame(&buf)
				if err != nil {
					b.Fatal(err)
				}
				_, compressed, err := DecodeBlockDataPayload(f.Payload)
				if err != nil {
					b.Fatal(err)
				}
				decompBuf, err = DecompressBlock(decompBuf, compressed, size)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkEndToEndZero measures end-to-end with zero blocks (skip-compressed).
func BenchmarkEndToEndZero(b *testing.B) {
	size := 4096
	src := make([]byte, size)

	hdr := BlockDataHeader{
		DeviceID:        1,
		BlockOffset:     0,
		UncompressedLen: uint32(size),
	}

	enc := &FrameEncoder{}
	dec := &FrameDecoder{}
	var compBuf, payloadBuf, decompBuf []byte
	var buf bytes.Buffer

	b.SetBytes(int64(size))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		compBuf, _ = CompressBlock(compBuf, src)
		if len(compBuf) == 0 {
			// zero block — sender would skip, but measure the detect cost
			continue
		}
		payloadBuf = EncodeBlockDataPayload(payloadBuf, hdr, compBuf)
		buf.Reset()
		enc.EncodeFrame(&buf, Frame{Type: MsgBlockData, Payload: payloadBuf})
		f, _ := dec.DecodeFrame(&buf)
		_, compressed, _ := DecodeBlockDataPayload(f.Payload)
		decompBuf, _ = DecompressBlock(decompBuf, compressed, size)
	}
}

func BenchmarkEncodeBlockDataPayload(b *testing.B) {
	h := BlockDataHeader{
		DeviceID:        1,
		BlockOffset:     4096,
		UncompressedLen: 4096,
	}
	compressed := make([]byte, 2048)
	rand.Read(compressed)
	var dst []byte

	b.SetBytes(int64(BlockDataHeaderSize + len(compressed)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dst = EncodeBlockDataPayload(dst, h, compressed)
	}
}
