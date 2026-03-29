package replproto

import (
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"sync"
)

// castagnoliTable is a pre-computed CRC32-C (Castagnoli) table.
// CRC32-C has hardware acceleration via SSE4.2 (x86) and ARMv8,
// giving 10-20x speedup over the software-only IEEE polynomial.
var castagnoliTable = crc32.MakeTable(crc32.Castagnoli)

// framePool reuses frame buffers to reduce allocations in the hot path.
var framePool = sync.Pool{
	New: func() any {
		// start with a reasonable default; grows as needed
		buf := make([]byte, 0, 4096)
		return &buf
	},
}

// wire protocol constants
const (
	FrameMagic      = 0x434C4844 // "CLHD" - cloudhound replication
	FrameHeaderSize = 9          // magic(4) + type(1) + length(4)
	FrameCRCSize    = 4
	MaxPayloadSize  = 16 << 20 // 16 MiB max payload
)

// message types
const (
	MsgAuth         byte = 0x01
	MsgAuthOK       byte = 0x02
	MsgAuthFail     byte = 0x03
	MsgDeviceInfo   byte = 0x10
	MsgBlockBitmap  byte = 0x11
	MsgBlockData    byte = 0x20
	MsgChecksumMap  byte = 0x21
	MsgDeltaRequest byte = 0x22
	MsgCommand      byte = 0x30
	MsgStatus       byte = 0x31
	MsgHeartbeat    byte = 0x32
	MsgAck          byte = 0x33
	MsgError        byte = 0x34
	MsgSyncComplete byte = 0x40
)

// Frame represents a single wire protocol frame
type Frame struct {
	Type    byte
	Payload []byte
}

// EncodeFrame writes a frame to the given writer
func EncodeFrame(w io.Writer, f Frame) error {
	payloadLen := len(f.Payload)
	if payloadLen > MaxPayloadSize {
		return fmt.Errorf("payload too large: %d > %d", payloadLen, MaxPayloadSize)
	}

	// build the frame: magic + type + length + payload + crc
	frameSize := FrameHeaderSize + payloadLen + FrameCRCSize

	bufp := framePool.Get().(*[]byte)
	buf := *bufp
	if cap(buf) < frameSize {
		buf = make([]byte, frameSize)
	} else {
		buf = buf[:frameSize]
	}

	// magic
	binary.BigEndian.PutUint32(buf[0:4], FrameMagic)
	// type
	buf[4] = f.Type
	// payload length
	binary.BigEndian.PutUint32(buf[5:9], uint32(payloadLen))
	// payload
	copy(buf[9:9+payloadLen], f.Payload)
	// crc32-c of everything before the crc
	crc := crc32.Checksum(buf[:9+payloadLen], castagnoliTable)
	binary.BigEndian.PutUint32(buf[9+payloadLen:], crc)

	_, err := w.Write(buf)

	*bufp = buf
	framePool.Put(bufp)

	return err
}

// DecodeFrame reads a single frame from the reader
func DecodeFrame(r io.Reader) (Frame, error) {
	// read header
	header := make([]byte, FrameHeaderSize)
	if _, err := io.ReadFull(r, header); err != nil {
		return Frame{}, fmt.Errorf("read header: %w", err)
	}

	// validate magic
	magic := binary.BigEndian.Uint32(header[0:4])
	if magic != FrameMagic {
		return Frame{}, fmt.Errorf("invalid magic: 0x%08X", magic)
	}

	msgType := header[4]
	payloadLen := binary.BigEndian.Uint32(header[5:9])

	if payloadLen > MaxPayloadSize {
		return Frame{}, fmt.Errorf("payload too large: %d", payloadLen)
	}

	// read payload + crc
	rest := make([]byte, payloadLen+FrameCRCSize)
	if _, err := io.ReadFull(r, rest); err != nil {
		return Frame{}, fmt.Errorf("read payload: %w", err)
	}

	// verify crc32-c incrementally over header + payload
	h := crc32.New(castagnoliTable)
	h.Write(header)
	h.Write(rest[:payloadLen])
	expected := h.Sum32()
	got := binary.BigEndian.Uint32(rest[payloadLen:])
	if got != expected {
		return Frame{}, fmt.Errorf("crc mismatch: expected 0x%08X, got 0x%08X", expected, got)
	}

	payload := make([]byte, payloadLen)
	copy(payload, rest[:payloadLen])

	return Frame{Type: msgType, Payload: payload}, nil
}

// block data binary payload helpers

// BlockDataHeader is the fixed-size header for BLOCK_DATA messages
type BlockDataHeader struct {
	DeviceID        uint16
	BlockOffset     uint64
	UncompressedLen uint32
	Checksum        [8]byte
}

// BlockDataHeaderSize is the byte size of a serialized BlockDataHeader
const BlockDataHeaderSize = 2 + 8 + 4 + 8 // 22 bytes

// EncodeBlockDataPayload builds a BLOCK_DATA payload from header + compressed data
func EncodeBlockDataPayload(h BlockDataHeader, compressedData []byte) []byte {
	buf := make([]byte, BlockDataHeaderSize+len(compressedData))
	binary.BigEndian.PutUint16(buf[0:2], h.DeviceID)
	binary.BigEndian.PutUint64(buf[2:10], h.BlockOffset)
	binary.BigEndian.PutUint32(buf[10:14], h.UncompressedLen)
	copy(buf[14:22], h.Checksum[:])
	copy(buf[22:], compressedData)
	return buf
}

// DecodeBlockDataPayload parses a BLOCK_DATA payload
func DecodeBlockDataPayload(data []byte) (BlockDataHeader, []byte, error) {
	if len(data) < BlockDataHeaderSize {
		return BlockDataHeader{}, nil, fmt.Errorf("block data payload too short: %d", len(data))
	}

	var h BlockDataHeader
	h.DeviceID = binary.BigEndian.Uint16(data[0:2])
	h.BlockOffset = binary.BigEndian.Uint64(data[2:10])
	h.UncompressedLen = binary.BigEndian.Uint32(data[10:14])
	copy(h.Checksum[:], data[14:22])

	compressed := data[22:]
	return h, compressed, nil
}

// rle bitmap encoding for BLOCK_BITMAP messages

// EncodeBitmapRLE encodes a bitmap using run-length encoding
// each run is: [4-byte count][1-byte value (0 or 1)]
func EncodeBitmapRLE(bitmap []byte, totalBlocks uint64) []byte {
	if len(bitmap) == 0 {
		return nil
	}

	// pre-allocate with a reasonable estimate to avoid per-run allocations
	result := make([]byte, 0, 256*5)
	var run [5]byte
	currentBit := (bitmap[0] >> 7) & 1
	count := uint32(0)

	for i := uint64(0); i < totalBlocks; i++ {
		byteIdx := i / 8
		bitIdx := 7 - (i % 8)
		var bit byte
		if byteIdx < uint64(len(bitmap)) {
			bit = (bitmap[byteIdx] >> bitIdx) & 1
		}

		if bit == currentBit {
			count++
		} else {
			// flush run
			binary.BigEndian.PutUint32(run[0:4], count)
			run[4] = currentBit
			result = append(result, run[:]...)
			currentBit = bit
			count = 1
		}
	}

	// flush final run
	if count > 0 {
		binary.BigEndian.PutUint32(run[0:4], count)
		run[4] = currentBit
		result = append(result, run[:]...)
	}

	return result
}

// DecodeBitmapRLE decodes an RLE-encoded bitmap
func DecodeBitmapRLE(data []byte, totalBlocks uint64) ([]byte, error) {
	bitmapSize := (totalBlocks + 7) / 8
	bitmap := make([]byte, bitmapSize)

	pos := uint64(0)
	offset := 0

	for offset+5 <= len(data) {
		count := binary.BigEndian.Uint32(data[offset : offset+4])
		value := data[offset+4]
		offset += 5

		for i := uint32(0); i < count && pos < totalBlocks; i++ {
			if value == 1 {
				byteIdx := pos / 8
				bitIdx := 7 - (pos % 8)
				bitmap[byteIdx] |= 1 << bitIdx
			}
			pos++
		}
	}

	return bitmap, nil
}
