package replproto

import (
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"math/bits"
	"net"
	"unsafe"
)

// castagnoliTable is a pre-computed CRC32-C (Castagnoli) table.
// CRC32-C has hardware acceleration via SSE4.2 (x86) and ARMv8,
// giving 10-20x speedup over the software-only IEEE polynomial.
var castagnoliTable = crc32.MakeTable(crc32.Castagnoli)

// bitMask[i] has the bit set at position i within a byte (MSB-first order).
// Used in decode loops to avoid per-iteration shift calculations.
var bitMask = [8]byte{0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01}

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

// FrameEncoder holds reusable state for encoding frames.
// Allocate one per goroutine for zero-GC frame encoding.
type FrameEncoder struct {
	hdr  [FrameHeaderSize]byte
	crc  [FrameCRCSize]byte
	bufs [3][]byte
}

// EncodeFrame writes a frame to the given writer using vectored IO.
// For *net.TCPConn this uses writev(2), avoiding the O(payload) copy
// into a contiguous buffer. For other writers, individual writes are
// performed (still no payload copy). Zero allocations after first call.
func (e *FrameEncoder) EncodeFrame(w io.Writer, f Frame) error {
	payloadLen := len(f.Payload)
	if payloadLen > MaxPayloadSize {
		return fmt.Errorf("payload too large: %d > %d", payloadLen, MaxPayloadSize)
	}

	// build header
	_ = e.hdr[8]
	binary.BigEndian.PutUint32(e.hdr[0:4], FrameMagic)
	e.hdr[4] = f.Type
	binary.BigEndian.PutUint32(e.hdr[5:9], uint32(payloadLen))

	// crc32-c over header + payload without copying payload
	crc := crc32.Update(0, castagnoliTable, e.hdr[:])
	crc = crc32.Update(crc, castagnoliTable, f.Payload)
	binary.BigEndian.PutUint32(e.crc[:], crc)

	// vectored write: writev(2) for net.TCPConn, sequential for others
	e.bufs[0] = e.hdr[:]
	e.bufs[1] = f.Payload
	e.bufs[2] = e.crc[:]
	bufs := net.Buffers(e.bufs[:])
	_, err := bufs.WriteTo(w)
	return err
}

// FrameData holds a prepared frame for deferred or zero-copy writing.
// It implements io.WriterTo — when writing to a *net.TCPConn, the
// kernel coalesces the header, payload, and CRC via writev(2).
type FrameData struct {
	hdr     [FrameHeaderSize]byte
	payload []byte
	crc     [FrameCRCSize]byte
}

// WriteTo implements io.WriterTo using vectored IO when available.
func (fd *FrameData) WriteTo(w io.Writer) (int64, error) {
	bufs := net.Buffers{fd.hdr[:], fd.payload, fd.crc[:]}
	return bufs.WriteTo(w)
}

// PrepareFrame builds a FrameData for deferred writing.
// The returned FrameData references f.Payload directly — the caller
// must keep it valid until WriteTo completes.
func (e *FrameEncoder) PrepareFrame(f Frame) (*FrameData, error) {
	payloadLen := len(f.Payload)
	if payloadLen > MaxPayloadSize {
		return nil, fmt.Errorf("payload too large: %d > %d", payloadLen, MaxPayloadSize)
	}

	fd := &FrameData{payload: f.Payload}
	binary.BigEndian.PutUint32(fd.hdr[0:4], FrameMagic)
	fd.hdr[4] = f.Type
	binary.BigEndian.PutUint32(fd.hdr[5:9], uint32(payloadLen))

	crc := crc32.Update(0, castagnoliTable, fd.hdr[:])
	crc = crc32.Update(crc, castagnoliTable, f.Payload)
	binary.BigEndian.PutUint32(fd.crc[:], crc)

	return fd, nil
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

	// verify crc32-c over header + payload using a single pass
	// by checksumming the contiguous header, then continuing into payload
	crcVal := crc32.Update(0, castagnoliTable, d.header[:])
	expected := crc32.Update(crcVal, castagnoliTable, d.buf[:payloadLen])
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

// EncodeBlockDataPayload builds a BLOCK_DATA payload from header + compressed data.
// dst is reused if large enough — pass the same slice across calls for zero-GC.
func EncodeBlockDataPayload(dst []byte, h BlockDataHeader, compressedData []byte) []byte {
	needed := BlockDataHeaderSize + len(compressedData)
	if cap(dst) >= needed {
		dst = dst[:needed]
	} else {
		dst = make([]byte, needed)
	}
	// single bounds-check elimination: reference element 21 to prove bounds
	_ = dst[21]
	binary.BigEndian.PutUint16(dst[0:2], h.DeviceID)
	binary.BigEndian.PutUint64(dst[2:10], h.BlockOffset)
	binary.BigEndian.PutUint32(dst[10:14], h.UncompressedLen)
	copy(dst[14:22], h.Checksum[:])
	copy(dst[22:], compressedData)
	return dst
}

// DecodeBlockDataPayload parses a BLOCK_DATA payload
func DecodeBlockDataPayload(data []byte) (BlockDataHeader, []byte, error) {
	if len(data) < BlockDataHeaderSize {
		return BlockDataHeader{}, nil, fmt.Errorf("block data payload too short: %d", len(data))
	}

	var h BlockDataHeader
	_ = data[21] // single bounds-check elimination
	h.DeviceID = binary.BigEndian.Uint16(data[0:2])
	h.BlockOffset = binary.BigEndian.Uint64(data[2:10])
	h.UncompressedLen = binary.BigEndian.Uint32(data[10:14])
	copy(h.Checksum[:], data[14:22])

	compressed := data[22:]
	return h, compressed, nil
}

// rle bitmap encoding for BLOCK_BITMAP messages

// EncodeBitmapRLE encodes a bitmap using run-length encoding.
// each run is: [4-byte count][1-byte value (0 or 1)]
// dst is reused if large enough — pass the same slice across calls for zero-GC.
func EncodeBitmapRLE(bitmap []byte, totalBlocks uint64) []byte {
	return AppendBitmapRLE(nil, bitmap, totalBlocks)
}

// AppendBitmapRLE is like EncodeBitmapRLE but reuses the dst buffer.
// dst is reused if large enough — pass the same slice across calls for zero-GC.
func AppendBitmapRLE(dst, bitmap []byte, totalBlocks uint64) []byte {
	if len(bitmap) == 0 {
		return dst[:0]
	}

	// estimate: assume ~1 transition per 64 bits on average
	estRuns := totalBlocks/64 + 2
	if estRuns < 16 {
		estRuns = 16
	}
	needed := int(estRuns * 5)
	if cap(dst) >= needed {
		dst = dst[:0]
	} else {
		dst = make([]byte, 0, needed)
	}

	currentBit := (bitmap[0] >> 7) & 1
	count := uint64(0)
	bitmapLen := uint64(len(bitmap))

	// Process in 64-bit (8-byte) words for O(transitions) instead of O(bytes).
	// Uniform-word checks use native-endian unsafe reads (0x00 and 0xFF words
	// are endian-neutral). BigEndian conversion only happens for mixed words
	// that need CLZ bit scanning.
	fullWords := totalBlocks / 64
	for wordIdx := uint64(0); wordIdx < fullWords; wordIdx++ {
		byteOff := wordIdx * 8
		var w uint64
		if byteOff+8 <= bitmapLen {
			w = *(*uint64)(unsafe.Pointer(&bitmap[byteOff]))
		}
		// else w = 0 (beyond bitmap, treat as zeros)

		// fast path: uniform word (all 0 or all 1) — endian-neutral
		if w == 0 || w == 0xFFFFFFFFFFFFFFFF {
			runBit := byte(0)
			if w != 0 {
				runBit = 1
			}
			// scan ahead for more identical words using unsafe reads
			runWords := uint64(1)
			for wordIdx+runWords < fullWords {
				nextOff := (wordIdx + runWords) * 8
				var next uint64
				if nextOff+8 <= bitmapLen {
					next = *(*uint64)(unsafe.Pointer(&bitmap[nextOff]))
				}
				if next != w {
					break
				}
				runWords++
			}
			wordIdx += runWords - 1 // outer loop increments

			if currentBit == runBit {
				count += runWords * 64
			} else {
				dst = appendRunLarge(dst, count, currentBit)
				currentBit = runBit
				count = runWords * 64
			}
			continue
		}

		// mixed word: convert to big-endian for MSB-first CLZ scanning
		wBE := binary.BigEndian.Uint64(bitmap[byteOff:])
		bitsLeft := uint(64)
		for bitsLeft > 0 {
			var mask uint64
			if currentBit == 1 {
				mask = 0xFFFFFFFFFFFFFFFF
			}
			diff := (wBE << (64 - bitsLeft)) ^ mask
			run := uint(bits.LeadingZeros64(diff))
			if run > bitsLeft {
				run = bitsLeft
			}
			count += uint64(run)
			bitsLeft -= run
			if bitsLeft > 0 {
				dst = appendRunLarge(dst, count, currentBit)
				currentBit ^= 1
				count = 0
			}
		}
	}

	// handle remaining tail bits (totalBlocks % 64)
	tailBits := totalBlocks & 63
	if tailBits > 0 {
		startByte := fullWords * 8
		// read available bytes into MSB of a uint64
		var buf [8]byte
		remainingBytes := (tailBits + 7) / 8
		for i := uint64(0); i < remainingBytes && startByte+i < bitmapLen; i++ {
			buf[i] = bitmap[startByte+i]
		}
		// zero out bits beyond tailBits in the last byte
		if tailBits&7 != 0 {
			buf[remainingBytes-1] &= ^byte(0xFF >> (tailBits & 7))
		}
		w := binary.BigEndian.Uint64(buf[:])

		bitsLeft := uint(tailBits)
		for bitsLeft > 0 {
			var mask uint64
			if currentBit == 1 {
				mask = 0xFFFFFFFFFFFFFFFF
			}
			diff := (w << (uint(tailBits) - bitsLeft)) ^ mask
			run := uint(bits.LeadingZeros64(diff))
			if run > bitsLeft {
				run = bitsLeft
			}
			count += uint64(run)
			bitsLeft -= run
			if bitsLeft > 0 {
				dst = appendRunLarge(dst, count, currentBit)
				currentBit ^= 1
				count = 0
			}
		}
	}

	// flush final run
	if count > 0 {
		dst = appendRunLarge(dst, count, currentBit)
	}

	return dst
}

// appendRunLarge handles counts that may exceed uint32. counts larger than
// MaxUint32 are split into multiple consecutive same-bit runs which the
// decoder handles naturally by accumulating offsets.
func appendRunLarge(dst []byte, count uint64, value byte) []byte {
	for count > 0xFFFFFFFF {
		dst = appendRun(dst, 0xFFFFFFFF, value)
		count -= 0xFFFFFFFF
	}
	return appendRun(dst, uint32(count), value)
}

// appendRun appends a 5-byte RLE run (count + value) to dst.
// Inlineable — avoids the intermediate [5]byte array + slice copy.
func appendRun(dst []byte, count uint32, value byte) []byte {
	return append(dst, byte(count>>24), byte(count>>16), byte(count>>8), byte(count), value)
}

// DecodeBitmapRLE decodes an RLE-encoded bitmap.
// dst is reused if large enough — pass the same slice across calls for zero-GC.
func DecodeBitmapRLE(data []byte, totalBlocks uint64) ([]byte, error) {
	return DecodeBitmapRLETo(nil, data, totalBlocks)
}

// DecodeBitmapRLETo is like DecodeBitmapRLE but reuses the dst buffer.
func DecodeBitmapRLETo(dst, data []byte, totalBlocks uint64) ([]byte, error) {
	bitmapSize := (totalBlocks + 7) / 8
	bitmap := grow(dst, int(bitmapSize))

	// Instead of pre-zeroing the entire bitmap and only writing 1-runs,
	// we write both 0-runs and 1-runs explicitly. This avoids the O(n)
	// zeroing pass which is wasteful for dense (mostly-1) bitmaps.
	// For reused buffers, we must write every byte since the buffer
	// may contain stale data.

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

		// Determine fill byte: 0x00 for zero-runs, 0xFF for one-runs
		var fillByte byte
		if value != 0 {
			fillByte = 0xFF
		}

		// handle unaligned leading bits using precomputed masks
		for pos < end && (pos&7) != 0 {
			m := bitMask[pos&7]
			if value != 0 {
				bitmap[pos>>3] |= m
			} else {
				bitmap[pos>>3] &^= m
			}
			pos++
		}

		// bulk fill aligned whole bytes using page-copy memset
		if pos+8 <= end {
			startByte := pos >> 3
			fillBytes := (end - pos) >> 3
			memset(bitmap[startByte:startByte+fillBytes], fillByte)
			pos += fillBytes * 8
		}

		// handle unaligned trailing bits using precomputed masks
		for pos < end {
			m := bitMask[pos&7]
			if value != 0 {
				bitmap[pos>>3] |= m
			} else {
				bitmap[pos>>3] &^= m
			}
			pos++
		}
	}

	// zero any remaining bits/bytes beyond the last run
	if pos < totalBlocks {
		// clear individual bits in the partial byte at pos
		for pos < totalBlocks && (pos&7) != 0 {
			bitmap[pos>>3] &^= bitMask[pos&7]
			pos++
		}
		// bulk zero remaining whole bytes
		startByte := pos >> 3
		if startByte < uint64(len(bitmap)) {
			memset(bitmap[startByte:], 0)
		}
	}

	return bitmap, nil
}
