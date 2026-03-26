package replproto

import "crypto/sha256"

// ComputeChecksum computes SHA-256 of a data block
func ComputeChecksum(data []byte) [32]byte {
	return sha256.Sum256(data)
}
