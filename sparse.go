package replproto

import (
	"encoding/binary"
)

// sparse region encoding for blocks that contain a mix of data and zero-filled
// regions. common with Windows VMs, database files, and NTFS sparse files where
// clusters are allocated but contain zeros.
//
// when a block has significant zero regions (>25% of the block), the sparse
// encoding is more efficient than flate compression because it can skip zero
// runs entirely rather than compressing them.
//
// sparse payload format (used within MsgBlockData compressed data area):
//   [SparseMarker(4)] [RegionCount(2)] [Region...]
//
// region format:
//   [Offset(4)] [Length(4)] [Data(Length)]
//
// only non-zero regions are included. the receiver fills the block with zeros
// first, then overwrites the non-zero regions at their offsets.

const (
	// sparseMarker is prepended to sparse-encoded payloads to distinguish
	// them from flate-compressed data. chosen to not collide with valid
	// flate headers (0x78xx, 0x08xx).
	sparseMarker = uint32(0x53505253) // "SPRS"

	// sparseMinZeroRun is the minimum length of a zero run to be worth
	// encoding as a gap. shorter runs are merged with adjacent data.
	sparseMinZeroRun = 512

	// sparseThresholdPct is the minimum fraction of zero bytes in a block
	// for sparse encoding to be attempted (25%).
	sparseThresholdPct = 25
)

// describes a contiguous non-zero region within a block
type sparseRegion struct {
	offset uint32
	length uint32
	data   []byte
}

// trySparseEncode analyzes a block for zero regions and returns a sparse
// encoding if beneficial. returns nil if the block doesn't benefit from
// sparse encoding (use regular compression instead).
func trySparseEncode(data []byte) []byte {
	if len(data) == 0 {
		return nil
	}

	// quick check: count zero bytes to see if sparse encoding is worthwhile
	zeroCount := 0
	for i := 0; i < len(data); i++ {
		if data[i] == 0 {
			zeroCount++
		}
	}

	threshold := len(data) * sparseThresholdPct / 100
	if zeroCount < threshold {
		return nil // not sparse enough
	}

	// find non-zero regions
	regions := findNonZeroRegions(data)
	if len(regions) == 0 {
		return nil // all zeros - let IsZeroBlock handle this
	}

	// calculate encoded size
	encodedSize := 4 + 2 // marker + region count
	dataBytes := 0
	for _, r := range regions {
		encodedSize += 4 + 4 + int(r.length) // offset + length + data
		dataBytes += int(r.length)
	}

	// only use sparse encoding if it saves significant space (>20% savings
	// compared to the raw data size that would need to be compressed)
	if float64(dataBytes) > float64(len(data))*0.80 {
		return nil // not enough savings
	}

	// encode
	buf := make([]byte, encodedSize)
	binary.BigEndian.PutUint32(buf[0:4], sparseMarker)
	binary.BigEndian.PutUint16(buf[4:6], uint16(len(regions)))

	offset := 6
	for _, r := range regions {
		binary.BigEndian.PutUint32(buf[offset:offset+4], r.offset)
		binary.BigEndian.PutUint32(buf[offset+4:offset+8], r.length)
		copy(buf[offset+8:offset+8+int(r.length)], r.data)
		offset += 8 + int(r.length)
	}

	return buf
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

// findNonZeroRegions scans a block and returns the non-zero regions,
// merging adjacent regions separated by short zero runs.
func findNonZeroRegions(data []byte) []sparseRegion {
	var regions []sparseRegion
	n := len(data)
	i := 0

	for i < n {
		// skip zero bytes
		for i < n && data[i] == 0 {
			i++
		}
		if i >= n {
			break
		}

		// found start of non-zero region
		start := i

		// scan forward, absorbing short zero runs
		for i < n {
			// find next zero run
			j := i
			for j < n && data[j] != 0 {
				j++
			}
			i = j

			// measure zero run length
			zeroStart := i
			for i < n && data[i] == 0 {
				i++
			}
			zeroLen := i - zeroStart

			// if zero run is short, absorb it into the region
			if zeroLen < sparseMinZeroRun && i < n {
				continue
			}

			// zero run is long enough to be a gap - end the region at zeroStart
			i = zeroStart
			break
		}

		end := i
		if end > start {
			regionData := make([]byte, end-start)
			copy(regionData, data[start:end])
			regions = append(regions, sparseRegion{
				offset: uint32(start),
				length: uint32(end - start),
				data:   regionData,
			})
		}
	}

	return regions
}
