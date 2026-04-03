package replproto

import xxhash "github.com/cespare/xxhash/v2"

// xxh64Sum delegates to cespare/xxhash which has its own asm on amd64
func xxh64Sum(b []byte) uint64 {
	return xxhash.Sum64(b)
}
