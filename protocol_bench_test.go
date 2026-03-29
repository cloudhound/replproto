package replproto

import (
	"bytes"
	"crypto/rand"
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

	b.SetBytes(int64(len(bitmap)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		EncodeBitmapRLE(bitmap, totalBlocks)
	}
}

func BenchmarkEncodeBitmapRLE_Dense(b *testing.B) {
	totalBlocks := uint64(8 * 1024 * 1024)
	bitmap := make([]byte, totalBlocks/8)
	for i := range bitmap {
		bitmap[i] = 0xFF
	}

	b.SetBytes(int64(len(bitmap)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		EncodeBitmapRLE(bitmap, totalBlocks)
	}
}

func BenchmarkDecodeBitmapRLE(b *testing.B) {
	totalBlocks := uint64(8 * 1024 * 1024)
	bitmap := make([]byte, totalBlocks/8)
	for i := range bitmap {
		bitmap[i] = 0xFF
	}
	encoded := EncodeBitmapRLE(bitmap, totalBlocks)

	b.SetBytes(int64(totalBlocks / 8))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DecodeBitmapRLE(encoded, totalBlocks)
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
