package replproto

import (
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
)

// castagnoliTable is a pre-computed CRC32-C (Castagnoli) table.
// CRC32-C has hardware acceleration via SSE4.2 (x86) and ARMv8,
// giving 10-20x speedup over the software-only IEEE polynomial.
var castagnoliTable = crc32.MakeTable(crc32.Castagnoli)

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

// FrameEncoder holds a reusable buffer for encoding frames.
// Allocate one per goroutine for zero-GC frame encoding.
type FrameEncoder struct {
	buf []byte
}

// EncodeFrame writes a frame to the given writer.
// The internal buffer is reused across calls — zero allocations
// after the first call with the largest frame size.
func (e *FrameEncoder) EncodeFrame(w io.Writer, f Frame) error {
	payloadLen := len(f.Payload)
	if payloadLen > MaxPayloadSize {
		return fmt.Errorf("payload too large: %d > %d", payloadLen, MaxPayloadSize)
	}

	// build the frame: magic + type + length + payload + crc
	frameSize := FrameHeaderSize + payloadLen + FrameCRCSize

	if cap(e.buf) < frameSize {
		e.buf = make([]byte, frameSize)
	} else {
		e.buf = e.buf[:frameSize]
	}

	// magic
	binary.BigEndian.PutUint32(e.buf[0:4], FrameMagic)
	// type
	e.buf[4] = f.Type
	// payload length
	binary.BigEndian.PutUint32(e.buf[5:9], uint32(payloadLen))
	// payload
	copy(e.buf[9:9+payloadLen], f.Payload)
	// crc32-c of everything before the crc
	crc := crc32.Checksum(e.buf[:9+payloadLen], castagnoliTable)
	binary.BigEndian.PutUint32(e.buf[9+payloadLen:], crc)

	_, err := w.Write(e.buf)
	return err
}

// FrameDecoder holds reusable buffers for decoding frames.
// Allocate one per goroutine for zero-GC frame decoding.
type FrameDecoder struct {
	header [FrameHeaderSize]byte
	buf    []byte
}

// DecodeFrame reads a single frame from the reader into caller-owned buffers.
// The returned Frame.Payload is valid until the next call to DecodeFrame.
func (d *FrameDecoder) DecodeFrame(r io.Reader) (Frame, error) {
	// read header into fixed-size array (no allocation)
	if _, err := io.ReadFull(r, d.header[:]); err != nil {
		return Frame{}, fmt.Errorf("read header: %w", err)
	}

	// validate magic
	magic := binary.BigEndian.Uint32(d.header[0:4])
	if magic != FrameMagic {
		return Frame{}, fmt.Errorf("invalid magic: 0x%08X", magic)
	}

	msgType := d.header[4]
	payloadLen := binary.BigEndian.Uint32(d.header[5:9])

	if payloadLen > MaxPayloadSize {
		return Frame{}, fmt.Errorf("payload too large: %d", payloadLen)
	}

	// reuse buffer for payload + crc
	needed := int(payloadLen) + FrameCRCSize
	if cap(d.buf) < needed {
		d.buf = make([]byte, needed)
	} else {
		d.buf = d.buf[:needed]
	}

	if _, err := io.ReadFull(r, d.buf); err != nil {
		return Frame{}, fmt.Errorf("read payload: %w", err)
	}

	// verify crc32-c over header + payload — no allocation
	expected := crc32.Update(
		crc32.Update(0, castagnoliTable, d.header[:]),
		castagnoliTable, d.buf[:payloadLen],
	)
	got := binary.BigEndian.Uint32(d.buf[payloadLen:])
	if got != expected {
		return Frame{}, fmt.Errorf("crc mismatch: expected 0x%08X, got 0x%08X", expected, got)
	}

	// return payload as a slice of the reusable buffer — no copy
	return Frame{Type: msgType, Payload: d.buf[:payloadLen]}, nil
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

	// estimate: assume ~1 transition per 64 bits on average
	estRuns := totalBlocks/64 + 2
	if estRuns < 16 {
		estRuns = 16
	}
	result := make([]byte, 0, estRuns*5)
	var run [5]byte

	currentBit := (bitmap[0] >> 7) & 1
	count := uint32(0)

	// number of full bytes covered by totalBlocks
	fullBytes := totalBlocks / 8
	tailBits := totalBlocks & 7

	for byteIdx := uint64(0); byteIdx < fullBytes; byteIdx++ {
		var b byte
		if byteIdx < uint64(len(bitmap)) {
			b = bitmap[byteIdx]
		}

		// fast path: entire byte is all-0 or all-1
		if b == 0x00 {
			if currentBit == 0 {
				count += 8
			} else {
				binary.BigEndian.PutUint32(run[0:4], count)
				run[4] = currentBit
				result = append(result, run[:]...)
				currentBit = 0
				count = 8
			}
			continue
		}
		if b == 0xFF {
			if currentBit == 1 {
				count += 8
			} else {
				binary.BigEndian.PutUint32(run[0:4], count)
				run[4] = currentBit
				result = append(result, run[:]...)
				currentBit = 1
				count = 8
			}
			continue
		}

		// slow path: mixed byte — process 8 bits
		for bitIdx := uint(7); ; bitIdx-- {
			bit := (b >> bitIdx) & 1
			if bit == currentBit {
				count++
			} else {
				binary.BigEndian.PutUint32(run[0:4], count)
				run[4] = currentBit
				result = append(result, run[:]...)
				currentBit = bit
				count = 1
			}
			if bitIdx == 0 {
				break
			}
		}
	}

	// handle remaining tail bits
	if tailBits > 0 {
		var b byte
		if fullBytes < uint64(len(bitmap)) {
			b = bitmap[fullBytes]
		}
		for bitIdx := uint(7); bitIdx > 7-uint(tailBits); bitIdx-- {
			bit := (b >> bitIdx) & 1
			if bit == currentBit {
				count++
			} else {
				binary.BigEndian.PutUint32(run[0:4], count)
				run[4] = currentBit
				result = append(result, run[:]...)
				currentBit = bit
				count = 1
			}
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
		count := uint64(binary.BigEndian.Uint32(data[offset : offset+4]))
		value := data[offset+4]
		offset += 5

		end := pos + count
		if end > totalBlocks {
			end = totalBlocks
		}

		if value == 0 {
			// bitmap is already zeroed — just advance
			pos = end
			continue
		}

		// value == 1: set bits from pos to end
		for pos < end {
			byteIdx := pos >> 3
			bitOff := 7 - (pos & 7)

			if bitOff == 7 && pos+8 <= end {
				// aligned and at least 8 bits: fill whole bytes
				fillEnd := (end - pos) >> 3 // number of full bytes
				for j := uint64(0); j < fillEnd; j++ {
					bitmap[byteIdx+j] = 0xFF
				}
				pos += fillEnd * 8
				continue
			}

			bitmap[byteIdx] |= 1 << bitOff
			pos++
		}
	}

	return bitmap, nil
}
