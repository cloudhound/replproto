package replproto

// ChecksumSize is the size of a block checksum in bytes (XXH64 = 8 bytes).
// consumers compute checksums using github.com/cespare/xxhash/v2 directly
// to keep replproto free of external dependencies.
const ChecksumSize = 8
