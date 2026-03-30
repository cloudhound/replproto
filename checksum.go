package replproto

import (
	"encoding/binary"

	xxhash "github.com/cespare/xxhash/v2"
)

// ChecksumSize is the size of a block checksum in bytes (XXH64 = 8 bytes).
const ChecksumSize = 8

// BlockChecksum computes the XXH64 checksum of a data block,
// returned as a big-endian 8-byte array matching the wire format.
func BlockChecksum(data []byte) [8]byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], xxhash.Sum64(data))
	return b
}
