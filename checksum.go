package replproto

import "encoding/binary"

// ChecksumSize is the size of a block checksum in bytes (XXH64 = 8 bytes).
const ChecksumSize = 8

// BlockChecksum computes the XXH64 checksum of a data block,
// returned as a big-endian 8-byte array matching the wire format.
// Zero blocks return a zero checksum without hashing.
func BlockChecksum(data []byte) [8]byte {
	if IsZeroBlock(data) {
		return [8]byte{}
	}
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], xxh64Sum(data))
	return b
}
