package replproto

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math"
	"testing"
)

// ---------- Frame encoding / decoding ----------

func TestFrameRoundTrip(t *testing.T) {
	msgTypes := []struct {
		name string
		typ  byte
	}{
		{"Auth", MsgAuth},
		{"AuthOK", MsgAuthOK},
		{"AuthFail", MsgAuthFail},
		{"DeviceInfo", MsgDeviceInfo},
		{"BlockBitmap", MsgBlockBitmap},
		{"BlockData", MsgBlockData},
		{"ChecksumMap", MsgChecksumMap},
		{"DeltaRequest", MsgDeltaRequest},
		{"Command", MsgCommand},
		{"Status", MsgStatus},
		{"Heartbeat", MsgHeartbeat},
		{"Ack", MsgAck},
		{"Error", MsgError},
		{"SyncComplete", MsgSyncComplete},
	}

	sizes := []int{0, 1, 22, 127, 4096, 64 * 1024}

	enc := &FrameEncoder{}
	dec := &FrameDecoder{}

	for _, mt := range msgTypes {
		for _, sz := range sizes {
			name := fmt.Sprintf("%s/size=%d", mt.name, sz)
			t.Run(name, func(t *testing.T) {
				payload := make([]byte, sz)
				if sz > 0 {
					rand.Read(payload)
				}
				f := Frame{Type: mt.typ, Payload: payload}

				var buf bytes.Buffer
				if err := enc.EncodeFrame(&buf, f); err != nil {
					t.Fatalf("EncodeFrame: %v", err)
				}

				got, err := dec.DecodeFrame(&buf)
				if err != nil {
					t.Fatalf("DecodeFrame: %v", err)
				}
				if got.Type != f.Type {
					t.Errorf("type: got 0x%02X, want 0x%02X", got.Type, f.Type)
				}
				if !bytes.Equal(got.Payload, f.Payload) {
					t.Errorf("payload mismatch (len got %d, want %d)", len(got.Payload), len(f.Payload))
				}
			})
		}
	}
}

func TestFrameMultipleSequential(t *testing.T) {
	enc := &FrameEncoder{}
	dec := &FrameDecoder{}
	var buf bytes.Buffer

	frames := make([]Frame, 50)
	for i := range frames {
		payload := make([]byte, i*37) // varying sizes
		rand.Read(payload)
		frames[i] = Frame{Type: byte(i % 256), Payload: payload}
		if err := enc.EncodeFrame(&buf, frames[i]); err != nil {
			t.Fatalf("encode frame %d: %v", i, err)
		}
	}

	reader := bytes.NewReader(buf.Bytes())
	for i, want := range frames {
		got, err := dec.DecodeFrame(reader)
		if err != nil {
			t.Fatalf("decode frame %d: %v", i, err)
		}
		if got.Type != want.Type {
			t.Errorf("frame %d type: got 0x%02X, want 0x%02X", i, got.Type, want.Type)
		}
		if !bytes.Equal(got.Payload, want.Payload) {
			t.Errorf("frame %d payload mismatch", i)
		}
	}
}

func TestFrameEncodePayloadTooLarge(t *testing.T) {
	enc := &FrameEncoder{}
	f := Frame{Type: MsgBlockData, Payload: make([]byte, MaxPayloadSize+1)}
	var buf bytes.Buffer
	if err := enc.EncodeFrame(&buf, f); err == nil {
		t.Fatal("expected error for oversized payload")
	}
}

func TestFrameDecodeInvalidMagic(t *testing.T) {
	dec := &FrameDecoder{}
	data := make([]byte, FrameHeaderSize+FrameCRCSize)
	binary.BigEndian.PutUint32(data[0:4], 0xDEADBEEF) // wrong magic
	data[4] = MsgHeartbeat
	binary.BigEndian.PutUint32(data[5:9], 0) // zero payload

	_, err := dec.DecodeFrame(bytes.NewReader(data))
	if err == nil {
		t.Fatal("expected error for invalid magic")
	}
}

func TestFrameDecodeCRCCorruption(t *testing.T) {
	enc := &FrameEncoder{}
	dec := &FrameDecoder{}

	payload := []byte("hello world")
	var buf bytes.Buffer
	enc.EncodeFrame(&buf, Frame{Type: MsgAuth, Payload: payload})

	raw := buf.Bytes()
	// flip a bit in the payload region
	raw[10] ^= 0xFF

	_, err := dec.DecodeFrame(bytes.NewReader(raw))
	if err == nil {
		t.Fatal("expected CRC error for corrupted frame")
	}
}

func TestFrameDecodeTruncated(t *testing.T) {
	enc := &FrameEncoder{}
	dec := &FrameDecoder{}

	payload := make([]byte, 100)
	rand.Read(payload)
	var buf bytes.Buffer
	enc.EncodeFrame(&buf, Frame{Type: MsgBlockData, Payload: payload})

	raw := buf.Bytes()
	// try decoding with only partial data
	_, err := dec.DecodeFrame(bytes.NewReader(raw[:FrameHeaderSize+10]))
	if err == nil {
		t.Fatal("expected error for truncated frame")
	}
}

func TestFrameDecodeEmptyReader(t *testing.T) {
	dec := &FrameDecoder{}
	_, err := dec.DecodeFrame(bytes.NewReader(nil))
	if err == nil {
		t.Fatal("expected error for empty reader")
	}
}

func TestFrameWireFormat(t *testing.T) {
	enc := &FrameEncoder{}
	payload := []byte{0xAA, 0xBB, 0xCC}
	var buf bytes.Buffer
	enc.EncodeFrame(&buf, Frame{Type: MsgHeartbeat, Payload: payload})

	raw := buf.Bytes()
	// verify magic
	if magic := binary.BigEndian.Uint32(raw[0:4]); magic != FrameMagic {
		t.Errorf("magic: got 0x%08X, want 0x%08X", magic, FrameMagic)
	}
	// verify type
	if raw[4] != MsgHeartbeat {
		t.Errorf("type: got 0x%02X, want 0x%02X", raw[4], MsgHeartbeat)
	}
	// verify length
	if plen := binary.BigEndian.Uint32(raw[5:9]); plen != 3 {
		t.Errorf("payload length: got %d, want 3", plen)
	}
	// verify payload bytes
	if !bytes.Equal(raw[9:12], payload) {
		t.Errorf("payload bytes mismatch")
	}
	// total frame size: header(9) + payload(3) + crc(4) = 16
	if len(raw) != 16 {
		t.Errorf("frame size: got %d, want 16", len(raw))
	}
}

// ---------- Block data payload encoding / decoding ----------

func TestBlockDataPayloadRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		hdr  BlockDataHeader
		data []byte
	}{
		{
			name: "typical",
			hdr: BlockDataHeader{
				DeviceID:        1,
				BlockOffset:     4096,
				UncompressedLen: 4096,
				Checksum:        [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
			},
			data: make([]byte, 2048),
		},
		{
			name: "empty_compressed_data",
			hdr: BlockDataHeader{
				DeviceID:        0,
				BlockOffset:     0,
				UncompressedLen: 0,
			},
			data: nil,
		},
		{
			name: "max_device_id",
			hdr: BlockDataHeader{
				DeviceID:        math.MaxUint16,
				BlockOffset:     math.MaxUint64,
				UncompressedLen: math.MaxUint32,
				Checksum:        [8]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
			},
			data: []byte{0xDE, 0xAD},
		},
		{
			name: "large_payload",
			hdr: BlockDataHeader{
				DeviceID:        42,
				BlockOffset:     1 << 40,
				UncompressedLen: 1 << 20,
			},
			data: make([]byte, 64*1024),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if len(tt.data) > 0 {
				rand.Read(tt.data)
			}

			encoded := EncodeBlockDataPayload(nil, tt.hdr, tt.data)
			gotHdr, gotData, err := DecodeBlockDataPayload(encoded)
			if err != nil {
				t.Fatalf("DecodeBlockDataPayload: %v", err)
			}
			if gotHdr.DeviceID != tt.hdr.DeviceID {
				t.Errorf("DeviceID: got %d, want %d", gotHdr.DeviceID, tt.hdr.DeviceID)
			}
			if gotHdr.BlockOffset != tt.hdr.BlockOffset {
				t.Errorf("BlockOffset: got %d, want %d", gotHdr.BlockOffset, tt.hdr.BlockOffset)
			}
			if gotHdr.UncompressedLen != tt.hdr.UncompressedLen {
				t.Errorf("UncompressedLen: got %d, want %d", gotHdr.UncompressedLen, tt.hdr.UncompressedLen)
			}
			if gotHdr.Checksum != tt.hdr.Checksum {
				t.Errorf("Checksum: got %x, want %x", gotHdr.Checksum, tt.hdr.Checksum)
			}
			if !bytes.Equal(gotData, tt.data) {
				t.Errorf("compressed data mismatch (len got %d, want %d)", len(gotData), len(tt.data))
			}
		})
	}
}

func TestBlockDataPayloadTooShort(t *testing.T) {
	for _, sz := range []int{0, 1, 10, 21} {
		_, _, err := DecodeBlockDataPayload(make([]byte, sz))
		if err == nil {
			t.Errorf("expected error for payload size %d", sz)
		}
	}
}

func TestBlockDataPayloadBufferReuse(t *testing.T) {
	hdr := BlockDataHeader{DeviceID: 1, BlockOffset: 100, UncompressedLen: 4096}
	data := make([]byte, 500)
	rand.Read(data)

	dst := make([]byte, 0, 1024)
	dst = EncodeBlockDataPayload(dst, hdr, data)

	// encode again with different data into same buffer
	hdr2 := BlockDataHeader{DeviceID: 2, BlockOffset: 200, UncompressedLen: 8192}
	data2 := make([]byte, 300)
	rand.Read(data2)
	dst = EncodeBlockDataPayload(dst, hdr2, data2)

	gotHdr, gotData, err := DecodeBlockDataPayload(dst)
	if err != nil {
		t.Fatal(err)
	}
	if gotHdr.DeviceID != 2 || gotHdr.BlockOffset != 200 {
		t.Errorf("header mismatch after reuse")
	}
	if !bytes.Equal(gotData, data2) {
		t.Errorf("data mismatch after reuse")
	}
}

func TestBlockDataPayloadWireFormat(t *testing.T) {
	hdr := BlockDataHeader{
		DeviceID:        0x0102,
		BlockOffset:     0x0304050607080910,
		UncompressedLen: 0x11121314,
		Checksum:        [8]byte{0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8},
	}
	data := []byte{0xBB, 0xCC}

	encoded := EncodeBlockDataPayload(nil, hdr, data)

	if len(encoded) != BlockDataHeaderSize+2 {
		t.Fatalf("encoded size: got %d, want %d", len(encoded), BlockDataHeaderSize+2)
	}
	// verify big-endian wire layout
	if binary.BigEndian.Uint16(encoded[0:2]) != 0x0102 {
		t.Error("DeviceID wire format wrong")
	}
	if binary.BigEndian.Uint64(encoded[2:10]) != 0x0304050607080910 {
		t.Error("BlockOffset wire format wrong")
	}
	if binary.BigEndian.Uint32(encoded[10:14]) != 0x11121314 {
		t.Error("UncompressedLen wire format wrong")
	}
	if !bytes.Equal(encoded[14:22], hdr.Checksum[:]) {
		t.Error("Checksum wire format wrong")
	}
	if !bytes.Equal(encoded[22:], data) {
		t.Error("compressed data wire format wrong")
	}
}

// ---------- Compression / decompression ----------

func TestCompressDecompressRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"random_4k", randBytes(4096)},
		{"random_64k", randBytes(64 * 1024)},
		{"random_1MB", randBytes(1 << 20)},
		{"repeating", bytes.Repeat([]byte("ABCDEFGH"), 4096)},
		{"single_byte", []byte{0x42}},
		{"two_bytes", []byte{0x01, 0x02}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compressed, checksum, err := CompressBlock(nil, tt.data)
			if err != nil {
				t.Fatalf("CompressBlock: %v", err)
			}
			decompressed, err := DecompressBlock(nil, compressed, len(tt.data), checksum)
			if err != nil {
				t.Fatalf("DecompressBlock: %v", err)
			}
			if !bytes.Equal(decompressed, tt.data) {
				t.Errorf("round-trip mismatch (len got %d, want %d)", len(decompressed), len(tt.data))
			}
		})
	}
}

func TestCompressBlockZeroDetection(t *testing.T) {
	for _, sz := range []int{1, 8, 32, 4096, 64 * 1024} {
		t.Run(fmt.Sprintf("size=%d", sz), func(t *testing.T) {
			src := make([]byte, sz)
			compressed, _, err := CompressBlock(nil, src)
			if err != nil {
				t.Fatalf("CompressBlock: %v", err)
			}
			if len(compressed) != 0 {
				t.Errorf("zero block should return empty slice, got len=%d", len(compressed))
			}
		})
	}
}

func TestCompressBlockBufferReuse(t *testing.T) {
	src1 := randBytes(4096)
	src2 := randBytes(4096)

	dst, _, _ := CompressBlock(nil, src1)
	dst, checksum, _ := CompressBlock(dst, src2)

	result, err := DecompressBlock(nil, dst, 4096, checksum)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(result, src2) {
		t.Error("decompressed data doesn't match second source after buffer reuse")
	}
}

func TestDecompressBlockErrors(t *testing.T) {
	t.Run("nil_src_zero_block", func(t *testing.T) {
		out, err := DecompressBlock(nil, nil, 100, [8]byte{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(out) != 100 {
			t.Fatalf("expected len=100, got %d", len(out))
		}
		if !IsZeroBlock(out) {
			t.Fatal("expected all zeros")
		}
	})
	t.Run("empty_src_zero_block", func(t *testing.T) {
		out, err := DecompressBlock(nil, []byte{}, 4096, [8]byte{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(out) != 4096 {
			t.Fatalf("expected len=4096, got %d", len(out))
		}
		if !IsZeroBlock(out) {
			t.Fatal("expected all zeros")
		}
	})
	t.Run("invalid_length_zero", func(t *testing.T) {
		_, err := DecompressBlock(nil, []byte{EncodingRaw, 0x01}, 0, [8]byte{})
		if err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("invalid_length_negative", func(t *testing.T) {
		_, err := DecompressBlock(nil, []byte{EncodingRaw, 0x01}, -1, [8]byte{})
		if err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("too_large", func(t *testing.T) {
		_, err := DecompressBlock(nil, []byte{EncodingRaw, 0x01}, MaxDecompressedSize+1, [8]byte{})
		if err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("unknown_tag", func(t *testing.T) {
		_, err := DecompressBlock(nil, []byte{0xFF, 0x01, 0x02}, 2, [8]byte{})
		if err == nil {
			t.Fatal("expected error")
		}
	})
}

func TestCompressBlockRawFallback(t *testing.T) {
	// highly random data that S2 can't compress well
	src := randBytes(4096)
	compressed, checksum, err := CompressBlock(nil, src)
	if err != nil {
		t.Fatal(err)
	}
	// regardless of encoding tag, round-trip must work
	result, err := DecompressBlock(nil, compressed, len(src), checksum)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(result, src) {
		t.Error("round-trip mismatch for random data")
	}
}

func TestIsZeroBlock(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{"nil", nil, true},
		{"empty", []byte{}, true},
		{"single_zero", []byte{0}, true},
		{"single_nonzero", []byte{1}, false},
		{"all_zero_4k", make([]byte, 4096), true},
		{"last_byte_set", append(make([]byte, 4095), 0x01), false},
		{"first_byte_set", append([]byte{0x01}, make([]byte, 4095)...), false},
		{"middle_byte_set", func() []byte {
			b := make([]byte, 4096)
			b[2048] = 0x01
			return b
		}(), false},
		// test sizes that exercise tail handling
		{"size_7", make([]byte, 7), true},
		{"size_9", make([]byte, 9), true},
		{"size_31", make([]byte, 31), true},
		{"size_33", make([]byte, 33), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsZeroBlock(tt.data); got != tt.want {
				t.Errorf("IsZeroBlock: got %v, want %v", got, tt.want)
			}
		})
	}
}

// ---------- Bitmap RLE encoding / decoding ----------

func TestBitmapRLERoundTrip(t *testing.T) {
	tests := []struct {
		name        string
		totalBlocks uint64
		bitmap      []byte
	}{
		{
			name:        "all_zeros_64",
			totalBlocks: 64,
			bitmap:      make([]byte, 8),
		},
		{
			name:        "all_ones_64",
			totalBlocks: 64,
			bitmap:      bytes.Repeat([]byte{0xFF}, 8),
		},
		{
			name:        "alternating_bytes",
			totalBlocks: 128,
			bitmap:      bytes.Repeat([]byte{0xAA}, 16),
		},
		{
			name:        "alternating_blocks",
			totalBlocks: 128,
			bitmap: func() []byte {
				b := make([]byte, 16)
				for i := 0; i < len(b); i += 2 {
					b[i] = 0xFF
				}
				return b
			}(),
		},
		{
			name:        "sparse_8M",
			totalBlocks: 8 * 1024 * 1024,
			bitmap: func() []byte {
				b := make([]byte, 1024*1024)
				for i := 0; i < len(b); i += 512 {
					b[i] = 0x80
				}
				return b
			}(),
		},
		{
			name:        "dense_8M",
			totalBlocks: 8 * 1024 * 1024,
			bitmap:      bytes.Repeat([]byte{0xFF}, 1024*1024),
		},
		{
			name:        "single_bit",
			totalBlocks: 1,
			bitmap:      []byte{0x80},
		},
		{
			name:        "single_bit_zero",
			totalBlocks: 1,
			bitmap:      []byte{0x00},
		},
		{
			name:        "7_bits",
			totalBlocks: 7,
			bitmap:      []byte{0b11111110},
		},
		{
			name:        "9_bits",
			totalBlocks: 9,
			bitmap:      []byte{0xFF, 0x80},
		},
		{
			name:        "non_byte_aligned_13",
			totalBlocks: 13,
			bitmap:      []byte{0b10101010, 0b10101000},
		},
		{
			name:        "large_run_then_flip",
			totalBlocks: 1024,
			bitmap: func() []byte {
				b := make([]byte, 128)
				// first 64 bytes all 1s, rest all 0s
				for i := 0; i < 64; i++ {
					b[i] = 0xFF
				}
				return b
			}(),
		},
		{
			name:        "many_transitions",
			totalBlocks: 256,
			bitmap: func() []byte {
				b := make([]byte, 32)
				// 0x55 = 01010101, maximum transitions
				for i := range b {
					b[i] = 0x55
				}
				return b
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded := EncodeBitmapRLE(tt.bitmap, tt.totalBlocks)
			decoded, err := DecodeBitmapRLE(encoded, tt.totalBlocks)
			if err != nil {
				t.Fatalf("DecodeBitmapRLE: %v", err)
			}

			// compare bit-by-bit up to totalBlocks
			for i := uint64(0); i < tt.totalBlocks; i++ {
				origBit := getBit(tt.bitmap, i)
				decodedBit := getBit(decoded, i)
				if origBit != decodedBit {
					t.Fatalf("bit %d: got %d, want %d", i, decodedBit, origBit)
				}
			}
		})
	}
}

func TestBitmapRLEAppendReuse(t *testing.T) {
	totalBlocks := uint64(128)
	bitmap1 := bytes.Repeat([]byte{0xF0}, 16)
	bitmap2 := bytes.Repeat([]byte{0x0F}, 16)

	dst := AppendBitmapRLE(nil, bitmap1, totalBlocks)
	// reuse dst for different bitmap
	dst = AppendBitmapRLE(dst, bitmap2, totalBlocks)

	decoded, err := DecodeBitmapRLE(dst, totalBlocks)
	if err != nil {
		t.Fatal(err)
	}
	for i := uint64(0); i < totalBlocks; i++ {
		if getBit(decoded, i) != getBit(bitmap2, i) {
			t.Fatalf("bit %d mismatch after reuse", i)
		}
	}
}

func TestBitmapRLEDecodeTo(t *testing.T) {
	totalBlocks := uint64(256)
	bitmap := bytes.Repeat([]byte{0xAB}, 32)

	encoded := EncodeBitmapRLE(bitmap, totalBlocks)

	// decode into pre-allocated buffer
	dst := make([]byte, 0, 64)
	decoded, err := DecodeBitmapRLETo(dst, encoded, totalBlocks)
	if err != nil {
		t.Fatal(err)
	}
	for i := uint64(0); i < totalBlocks; i++ {
		if getBit(decoded, i) != getBit(bitmap, i) {
			t.Fatalf("bit %d mismatch", i)
		}
	}
}

func TestBitmapRLEDecodeStaleBuffer(t *testing.T) {
	// ensure DecodeBitmapRLETo overwrites stale data in reused buffer
	totalBlocks := uint64(64)
	bitmap := make([]byte, 8) // all zeros

	encoded := EncodeBitmapRLE(bitmap, totalBlocks)

	// pre-fill dst with 0xFF (stale data)
	dst := bytes.Repeat([]byte{0xFF}, 8)
	decoded, err := DecodeBitmapRLETo(dst, encoded, totalBlocks)
	if err != nil {
		t.Fatal(err)
	}
	for i := uint64(0); i < totalBlocks; i++ {
		if getBit(decoded, i) != 0 {
			t.Fatalf("bit %d should be 0 (stale data not cleared)", i)
		}
	}
}

func TestBitmapRLEEmptyBitmap(t *testing.T) {
	result := EncodeBitmapRLE(nil, 0)
	if len(result) != 0 {
		t.Errorf("expected empty result for nil bitmap, got len=%d", len(result))
	}

	result = EncodeBitmapRLE([]byte{}, 0)
	if len(result) != 0 {
		t.Errorf("expected empty result for empty bitmap, got len=%d", len(result))
	}
}

func TestBitmapRLEEncodedFormat(t *testing.T) {
	// 8 bits all set → should encode as single run: count=8, value=1
	totalBlocks := uint64(8)
	bitmap := []byte{0xFF}
	encoded := EncodeBitmapRLE(bitmap, totalBlocks)

	if len(encoded) != 5 {
		t.Fatalf("expected 5 bytes (one run), got %d", len(encoded))
	}
	count := binary.BigEndian.Uint32(encoded[0:4])
	value := encoded[4]
	if count != 8 {
		t.Errorf("run count: got %d, want 8", count)
	}
	if value != 1 {
		t.Errorf("run value: got %d, want 1", value)
	}
}

// ---------- Full end-to-end pipeline tests ----------

func TestEndToEndBlockDataPipeline(t *testing.T) {
	sizes := []int{1, 32, 4096, 64 * 1024, 256 * 1024}

	for _, sz := range sizes {
		t.Run(fmt.Sprintf("size=%d", sz), func(t *testing.T) {
			original := randBytes(sz)

			// --- sender side ---
			compressed, checksum, err := CompressBlock(nil, original)
			if err != nil {
				t.Fatalf("CompressBlock: %v", err)
			}

			hdr := BlockDataHeader{
				DeviceID:        7,
				BlockOffset:     12345678,
				UncompressedLen: uint32(sz),
				Checksum:        checksum,
			}
			payload := EncodeBlockDataPayload(nil, hdr, compressed)

			enc := &FrameEncoder{}
			var buf bytes.Buffer
			if err := enc.EncodeFrame(&buf, Frame{Type: MsgBlockData, Payload: payload}); err != nil {
				t.Fatalf("EncodeFrame: %v", err)
			}

			// --- receiver side ---
			dec := &FrameDecoder{}
			frame, err := dec.DecodeFrame(&buf)
			if err != nil {
				t.Fatalf("DecodeFrame: %v", err)
			}
			if frame.Type != MsgBlockData {
				t.Fatalf("frame type: got 0x%02X, want 0x%02X", frame.Type, MsgBlockData)
			}

			gotHdr, gotCompressed, err := DecodeBlockDataPayload(frame.Payload)
			if err != nil {
				t.Fatalf("DecodeBlockDataPayload: %v", err)
			}
			if gotHdr != hdr {
				t.Errorf("header mismatch: got %+v, want %+v", gotHdr, hdr)
			}

			decompressed, err := DecompressBlock(nil, gotCompressed, int(gotHdr.UncompressedLen), gotHdr.Checksum)
			if err != nil {
				t.Fatalf("DecompressBlock: %v", err)
			}
			if !bytes.Equal(decompressed, original) {
				t.Errorf("data mismatch after full pipeline (len got %d, want %d)", len(decompressed), len(original))
			}
		})
	}
}

func TestEndToEndBlockDataZero(t *testing.T) {
	original := make([]byte, 4096)

	compressed, checksum, err := CompressBlock(nil, original)
	if err != nil {
		t.Fatal(err)
	}
	// zero blocks produce empty compressed output and zero checksum
	if len(compressed) != 0 {
		t.Fatalf("expected empty compressed for zero block, got len=%d", len(compressed))
	}
	if checksum != ([8]byte{}) {
		t.Fatalf("expected zero checksum for zero block, got %x", checksum)
	}

	// full round-trip: decompress the zero block
	decompressed, err := DecompressBlock(nil, compressed, len(original), checksum)
	if err != nil {
		t.Fatalf("DecompressBlock: %v", err)
	}
	if !bytes.Equal(decompressed, original) {
		t.Error("round-trip mismatch for zero block")
	}
}

func TestEndToEndBitmapPipeline(t *testing.T) {
	totalBlocks := uint64(1024 * 8) // 1KB bitmap
	bitmap := make([]byte, totalBlocks/8)
	// create a pattern: first quarter set, rest clear
	for i := 0; i < len(bitmap)/4; i++ {
		bitmap[i] = 0xFF
	}

	// encode bitmap
	rleData := EncodeBitmapRLE(bitmap, totalBlocks)

	// wrap in frame
	enc := &FrameEncoder{}
	var buf bytes.Buffer
	if err := enc.EncodeFrame(&buf, Frame{Type: MsgBlockBitmap, Payload: rleData}); err != nil {
		t.Fatal(err)
	}

	// decode frame
	dec := &FrameDecoder{}
	frame, err := dec.DecodeFrame(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if frame.Type != MsgBlockBitmap {
		t.Fatalf("type: got 0x%02X, want 0x%02X", frame.Type, MsgBlockBitmap)
	}

	// decode bitmap
	decoded, err := DecodeBitmapRLE(frame.Payload, totalBlocks)
	if err != nil {
		t.Fatal(err)
	}

	for i := uint64(0); i < totalBlocks; i++ {
		if getBit(decoded, i) != getBit(bitmap, i) {
			t.Fatalf("bit %d mismatch", i)
		}
	}
}

func TestEndToEndMultiFrameStream(t *testing.T) {
	enc := &FrameEncoder{}
	dec := &FrameDecoder{}
	var buf bytes.Buffer

	// simulate a realistic stream: auth → device info → bitmap → block data × N → sync complete
	type step struct {
		msgType byte
		payload []byte
	}

	totalBlocks := uint64(512)
	bitmap := bytes.Repeat([]byte{0xFF}, int(totalBlocks/8))
	rleData := EncodeBitmapRLE(bitmap, totalBlocks)

	blockData := randBytes(4096)
	compressed, _, _ := CompressBlock(nil, blockData)
	hdr := BlockDataHeader{DeviceID: 1, BlockOffset: 0, UncompressedLen: 4096}
	blockPayload := EncodeBlockDataPayload(nil, hdr, compressed)

	steps := []step{
		{MsgAuth, []byte("token123")},
		{MsgAuthOK, nil},
		{MsgDeviceInfo, []byte("device-metadata")},
		{MsgBlockBitmap, rleData},
		{MsgBlockData, blockPayload},
		{MsgBlockData, blockPayload},
		{MsgBlockData, blockPayload},
		{MsgAck, []byte{0x01}},
		{MsgSyncComplete, nil},
	}

	// encode all frames
	for _, s := range steps {
		if err := enc.EncodeFrame(&buf, Frame{Type: s.msgType, Payload: s.payload}); err != nil {
			t.Fatal(err)
		}
	}

	// decode and verify
	reader := bytes.NewReader(buf.Bytes())
	for i, s := range steps {
		frame, err := dec.DecodeFrame(reader)
		if err != nil {
			t.Fatalf("step %d: %v", i, err)
		}
		if frame.Type != s.msgType {
			t.Errorf("step %d type: got 0x%02X, want 0x%02X", i, frame.Type, s.msgType)
		}
		if !bytes.Equal(frame.Payload, s.payload) {
			t.Errorf("step %d payload mismatch", i)
		}
	}
}

func TestEndToEndCompressDecompressAllPatterns(t *testing.T) {
	patterns := []struct {
		name string
		data []byte
	}{
		{"zeros", make([]byte, 4096)},
		{"ones", bytes.Repeat([]byte{0xFF}, 4096)},
		{"random", randBytes(4096)},
		{"compressible", bytes.Repeat([]byte("The quick brown fox jumps over the lazy dog. "), 100)},
		{"single_value", bytes.Repeat([]byte{0x42}, 4096)},
		{"ascending", func() []byte {
			b := make([]byte, 4096)
			for i := range b {
				b[i] = byte(i)
			}
			return b
		}()},
		{"two_halves", func() []byte {
			b := make([]byte, 4096)
			for i := 2048; i < 4096; i++ {
				b[i] = 0xFF
			}
			return b
		}()},
	}

	for _, p := range patterns {
		t.Run(p.name, func(t *testing.T) {
			compressed, checksum, err := CompressBlock(nil, p.data)
			if err != nil {
				t.Fatalf("CompressBlock: %v", err)
			}

			if len(compressed) == 0 {
				// zero block shortcut
				if !IsZeroBlock(p.data) {
					t.Fatal("empty compressed output for non-zero block")
				}
				return
			}

			decompressed, err := DecompressBlock(nil, compressed, len(p.data), checksum)
			if err != nil {
				t.Fatalf("DecompressBlock: %v", err)
			}
			if !bytes.Equal(decompressed, p.data) {
				t.Error("round-trip data mismatch")
			}
		})
	}
}

func TestEndToEndLargeBlockWithFrame(t *testing.T) {
	// test with 1 MiB block through the full pipeline
	sz := 1 << 20
	original := randBytes(sz)

	compressed, checksum, err := CompressBlock(nil, original)
	if err != nil {
		t.Fatal(err)
	}

	hdr := BlockDataHeader{
		DeviceID:        100,
		BlockOffset:     999999,
		UncompressedLen: uint32(sz),
		Checksum:        checksum,
	}
	payload := EncodeBlockDataPayload(nil, hdr, compressed)

	enc := &FrameEncoder{}
	dec := &FrameDecoder{}
	var buf bytes.Buffer

	if err := enc.EncodeFrame(&buf, Frame{Type: MsgBlockData, Payload: payload}); err != nil {
		t.Fatal(err)
	}

	frame, err := dec.DecodeFrame(&buf)
	if err != nil {
		t.Fatal(err)
	}

	gotHdr, gotCompressed, err := DecodeBlockDataPayload(frame.Payload)
	if err != nil {
		t.Fatal(err)
	}

	decompressed, err := DecompressBlock(nil, gotCompressed, int(gotHdr.UncompressedLen), gotHdr.Checksum)
	if err != nil {
		t.Fatal(err)
	}

	if gotHdr.DeviceID != 100 || gotHdr.BlockOffset != 999999 {
		t.Error("header values wrong")
	}
	if !bytes.Equal(decompressed, original) {
		t.Error("1 MiB round-trip data mismatch")
	}
}

func TestEndToEndBitmapVariousDensities(t *testing.T) {
	totalBlocks := uint64(4096)
	bitmapSize := int(totalBlocks / 8)

	densities := []struct {
		name string
		fill func([]byte)
	}{
		{"empty", func(b []byte) {}},
		{"full", func(b []byte) {
			for i := range b {
				b[i] = 0xFF
			}
		}},
		{"50pct", func(b []byte) {
			for i := range b {
				b[i] = 0xAA
			}
		}},
		{"1pct_sparse", func(b []byte) {
			for i := 0; i < len(b); i += 100 {
				b[i] = 0x80
			}
		}},
		{"99pct_dense", func(b []byte) {
			for i := range b {
				b[i] = 0xFF
			}
			for i := 0; i < len(b); i += 100 {
				b[i] = 0x7F
			}
		}},
		{"random", func(b []byte) {
			rand.Read(b)
		}},
	}

	for _, d := range densities {
		t.Run(d.name, func(t *testing.T) {
			bitmap := make([]byte, bitmapSize)
			d.fill(bitmap)

			encoded := EncodeBitmapRLE(bitmap, totalBlocks)

			// wrap in frame
			enc := &FrameEncoder{}
			var buf bytes.Buffer
			enc.EncodeFrame(&buf, Frame{Type: MsgBlockBitmap, Payload: encoded})

			dec := &FrameDecoder{}
			frame, err := dec.DecodeFrame(&buf)
			if err != nil {
				t.Fatal(err)
			}

			decoded, err := DecodeBitmapRLE(frame.Payload, totalBlocks)
			if err != nil {
				t.Fatal(err)
			}

			for i := uint64(0); i < totalBlocks; i++ {
				if getBit(decoded, i) != getBit(bitmap, i) {
					t.Fatalf("bit %d mismatch", i)
				}
			}
		})
	}
}

// ---------- PrepareFrame / FrameData ----------

func TestPrepareFrameRoundTrip(t *testing.T) {
	enc := &FrameEncoder{}
	dec := &FrameDecoder{}

	sizes := []int{0, 1, 22, 4096, 64 * 1024}
	for _, sz := range sizes {
		t.Run(fmt.Sprintf("size=%d", sz), func(t *testing.T) {
			payload := make([]byte, sz)
			if sz > 0 {
				rand.Read(payload)
			}

			fd, err := enc.PrepareFrame(Frame{Type: MsgBlockData, Payload: payload})
			if err != nil {
				t.Fatalf("PrepareFrame: %v", err)
			}

			var buf bytes.Buffer
			if _, err := fd.WriteTo(&buf); err != nil {
				t.Fatalf("WriteTo: %v", err)
			}

			got, err := dec.DecodeFrame(&buf)
			if err != nil {
				t.Fatalf("DecodeFrame: %v", err)
			}
			if got.Type != MsgBlockData {
				t.Errorf("type: got 0x%02X, want 0x%02X", got.Type, MsgBlockData)
			}
			if !bytes.Equal(got.Payload, payload) {
				t.Errorf("payload mismatch (len got %d, want %d)", len(got.Payload), len(payload))
			}
		})
	}
}

func TestPrepareFramePayloadTooLarge(t *testing.T) {
	enc := &FrameEncoder{}
	_, err := enc.PrepareFrame(Frame{Type: MsgBlockData, Payload: make([]byte, MaxPayloadSize+1)})
	if err == nil {
		t.Fatal("expected error for oversized payload")
	}
}

func TestPrepareFrameMatchesEncodeFrame(t *testing.T) {
	enc := &FrameEncoder{}
	payload := randBytes(512)
	f := Frame{Type: MsgChecksumMap, Payload: payload}

	// encode via EncodeFrame
	var buf1 bytes.Buffer
	if err := enc.EncodeFrame(&buf1, f); err != nil {
		t.Fatal(err)
	}

	// encode via PrepareFrame + WriteTo
	fd, err := enc.PrepareFrame(f)
	if err != nil {
		t.Fatal(err)
	}
	var buf2 bytes.Buffer
	if _, err := fd.WriteTo(&buf2); err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(buf1.Bytes(), buf2.Bytes()) {
		t.Error("PrepareFrame wire output differs from EncodeFrame")
	}
}

// ---------- Frame decode edge cases ----------

func TestFrameDecodePayloadLengthAtMax(t *testing.T) {
	// craft a header that claims payload length = MaxPayloadSize+1
	dec := &FrameDecoder{}
	var hdr [FrameHeaderSize]byte
	binary.BigEndian.PutUint32(hdr[0:4], FrameMagic)
	hdr[4] = MsgBlockData
	binary.BigEndian.PutUint32(hdr[5:9], MaxPayloadSize+1)

	_, err := dec.DecodeFrame(bytes.NewReader(hdr[:]))
	if err == nil {
		t.Fatal("expected error for payload length exceeding max")
	}
}

func TestFrameDecodeCRCCorruptionInHeader(t *testing.T) {
	enc := &FrameEncoder{}
	dec := &FrameDecoder{}

	payload := []byte("test payload")
	var buf bytes.Buffer
	enc.EncodeFrame(&buf, Frame{Type: MsgAuth, Payload: payload})

	raw := buf.Bytes()
	// flip a bit in the type field (header region, not payload)
	raw[4] ^= 0x01

	_, err := dec.DecodeFrame(bytes.NewReader(raw))
	if err == nil {
		t.Fatal("expected CRC error for header corruption")
	}
}

func TestFrameDecodeCRCCorruptionInCRC(t *testing.T) {
	enc := &FrameEncoder{}
	dec := &FrameDecoder{}

	payload := []byte("test payload")
	var buf bytes.Buffer
	enc.EncodeFrame(&buf, Frame{Type: MsgAuth, Payload: payload})

	raw := buf.Bytes()
	// flip last byte (the CRC itself)
	raw[len(raw)-1] ^= 0xFF

	_, err := dec.DecodeFrame(bytes.NewReader(raw))
	if err == nil {
		t.Fatal("expected CRC error for corrupted CRC field")
	}
}

func TestFrameDecodeHeaderTruncated(t *testing.T) {
	dec := &FrameDecoder{}
	// only 5 bytes of a 9-byte header
	partial := make([]byte, 5)
	binary.BigEndian.PutUint32(partial[0:4], FrameMagic)
	partial[4] = MsgHeartbeat

	_, err := dec.DecodeFrame(bytes.NewReader(partial))
	if err == nil {
		t.Fatal("expected error for truncated header")
	}
}

// ---------- Bitmap RLE decode edge cases ----------

func TestBitmapRLEDecodeEmptyData(t *testing.T) {
	// empty encoded data with non-zero totalBlocks should produce a zeroed bitmap
	decoded, err := DecodeBitmapRLE(nil, 64)
	if err != nil {
		t.Fatal(err)
	}
	for i := uint64(0); i < 64; i++ {
		if getBit(decoded, i) != 0 {
			t.Fatalf("bit %d should be 0 for empty encoded data", i)
		}
	}
}

func TestBitmapRLEDecodeTruncatedRun(t *testing.T) {
	// 3 bytes of a 5-byte run should be ignored (offset+5 > len check)
	truncated := []byte{0x00, 0x00, 0x08}
	decoded, err := DecodeBitmapRLE(truncated, 64)
	if err != nil {
		t.Fatal(err)
	}
	// should produce zeroed bitmap since the partial run is skipped
	for i := uint64(0); i < 64; i++ {
		if getBit(decoded, i) != 0 {
			t.Fatalf("bit %d should be 0 for truncated run data", i)
		}
	}
}

func TestBitmapRLEDecodeRunExceedsTotalBlocks(t *testing.T) {
	// encode a run of 1000 bits, but decode with totalBlocks=64
	// the run should be clamped to totalBlocks
	var encoded []byte
	encoded = appendRun(encoded, 1000, 1)

	decoded, err := DecodeBitmapRLE(encoded, 64)
	if err != nil {
		t.Fatal(err)
	}
	for i := uint64(0); i < 64; i++ {
		if getBit(decoded, i) != 1 {
			t.Fatalf("bit %d should be 1", i)
		}
	}
	// bitmap should be exactly 8 bytes (64/8)
	if len(decoded) != 8 {
		t.Errorf("bitmap size: got %d, want 8", len(decoded))
	}
}

func TestBitmapRLEDecodeMultipleRunsExceedTotalBlocks(t *testing.T) {
	// two runs that together exceed totalBlocks
	var encoded []byte
	encoded = appendRun(encoded, 32, 1)
	encoded = appendRun(encoded, 1000, 0) // second run overshoots

	decoded, err := DecodeBitmapRLE(encoded, 48)
	if err != nil {
		t.Fatal(err)
	}
	for i := uint64(0); i < 32; i++ {
		if getBit(decoded, i) != 1 {
			t.Fatalf("bit %d should be 1", i)
		}
	}
	for i := uint64(32); i < 48; i++ {
		if getBit(decoded, i) != 0 {
			t.Fatalf("bit %d should be 0", i)
		}
	}
}

func TestBitmapRLERandomRoundTrip(t *testing.T) {
	// fuzz-like: random bitmaps at various sizes including non-byte-aligned
	for _, totalBlocks := range []uint64{1, 3, 7, 8, 9, 15, 16, 17, 63, 64, 65, 127, 128, 129, 255, 256, 500, 1023, 1024, 4095, 4096} {
		bitmapSize := (totalBlocks + 7) / 8
		bitmap := make([]byte, bitmapSize)
		rand.Read(bitmap)
		// clear bits beyond totalBlocks in the last byte
		if totalBlocks%8 != 0 {
			bitmap[len(bitmap)-1] &= ^byte(0xFF >> (totalBlocks % 8))
		}

		encoded := EncodeBitmapRLE(bitmap, totalBlocks)
		decoded, err := DecodeBitmapRLE(encoded, totalBlocks)
		if err != nil {
			t.Fatalf("totalBlocks=%d: %v", totalBlocks, err)
		}
		for i := uint64(0); i < totalBlocks; i++ {
			if getBit(decoded, i) != getBit(bitmap, i) {
				t.Fatalf("totalBlocks=%d bit %d: got %d, want %d", totalBlocks, i, getBit(decoded, i), getBit(bitmap, i))
			}
		}
	}
}

// ---------- isZeroBlockGeneric ----------

func TestIsZeroBlockGeneric(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{"nil", nil, true},
		{"empty", []byte{}, true},
		{"single_zero", []byte{0}, true},
		{"single_nonzero", []byte{1}, false},
		{"all_zero_4k", make([]byte, 4096), true},
		{"last_byte_set", append(make([]byte, 4095), 0x01), false},
		{"first_byte_set", append([]byte{0x01}, make([]byte, 4095)...), false},
		{"size_7", make([]byte, 7), true},
		{"size_9", make([]byte, 9), true},
		{"size_31", make([]byte, 31), true},
		{"size_33", make([]byte, 33), true},
		// sizes that exercise each loop stage
		{"size_8_nonzero_last", func() []byte {
			b := make([]byte, 8)
			b[7] = 1
			return b
		}(), false},
		{"size_32_nonzero_last_word", func() []byte {
			b := make([]byte, 32)
			b[24] = 1
			return b
		}(), false},
		{"size_40_tail", func() []byte {
			b := make([]byte, 40)
			b[39] = 1
			return b
		}(), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isZeroBlockGeneric(tt.data); got != tt.want {
				t.Errorf("isZeroBlockGeneric: got %v, want %v", got, tt.want)
			}
		})
	}
}

// ---------- DecompressBlock buffer reuse ----------

func TestDecompressBlockBufferReuse(t *testing.T) {
	src1 := randBytes(4096)
	src2 := randBytes(4096)

	comp1, checksum1, _ := CompressBlock(nil, src1)
	comp2, checksum2, _ := CompressBlock(nil, src2)

	dst, err := DecompressBlock(nil, comp1, 4096, checksum1)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dst, src1) {
		t.Fatal("first decompress mismatch")
	}

	// reuse dst for second decompress
	dst, err = DecompressBlock(dst, comp2, 4096, checksum2)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dst, src2) {
		t.Fatal("second decompress mismatch after buffer reuse")
	}
}

func TestDecompressBlockRawEncoding(t *testing.T) {
	// manually craft a raw-encoded payload
	src := randBytes(100)
	raw := make([]byte, 1+len(src))
	raw[0] = EncodingRaw
	copy(raw[1:], src)

	dst, err := DecompressBlock(nil, raw, len(src), [8]byte{})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dst, src) {
		t.Error("raw encoding decompress mismatch")
	}
}

// ---------- memset ----------

func TestMemset(t *testing.T) {
	// test zero fill
	buf := bytes.Repeat([]byte{0xAA}, 8192)
	memset(buf, 0)
	for i, b := range buf {
		if b != 0 {
			t.Fatalf("memset(0): byte %d = 0x%02X, want 0x00", i, b)
		}
	}

	// test 0xFF fill
	memset(buf, 0xFF)
	for i, b := range buf {
		if b != 0xFF {
			t.Fatalf("memset(0xFF): byte %d = 0x%02X, want 0xFF", i, b)
		}
	}

	// test odd-sized buffer (not page-aligned)
	small := make([]byte, 137)
	memset(small, 0xFF)
	for i, b := range small {
		if b != 0xFF {
			t.Fatalf("memset small: byte %d = 0x%02X, want 0xFF", i, b)
		}
	}
}

// ---------- grow helper ----------

func TestGrow(t *testing.T) {
	// nil buffer
	buf := grow(nil, 10)
	if len(buf) != 10 {
		t.Fatalf("grow(nil, 10): len=%d", len(buf))
	}

	// reuse existing capacity
	buf = make([]byte, 5, 100)
	result := grow(buf, 50)
	if len(result) != 50 || cap(result) != 100 {
		t.Fatalf("grow reuse: len=%d cap=%d, want len=50 cap=100", len(result), cap(result))
	}

	// must allocate new buffer
	buf = make([]byte, 5, 10)
	result = grow(buf, 20)
	if len(result) != 20 {
		t.Fatalf("grow new alloc: len=%d, want 20", len(result))
	}
}

// ---------- helpers ----------

func randBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

func getBit(bitmap []byte, idx uint64) byte {
	if idx/8 >= uint64(len(bitmap)) {
		return 0
	}
	return (bitmap[idx/8] >> (7 - (idx & 7))) & 1
}
