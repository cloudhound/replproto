//go:build arm64

package replproto

// assembly declaration — implementation in xxh64_arm64.s
// hand-tuned scalar arm64: LDP for 16-byte loads, MADD for fused
// multiply-add, ROR for rotation. NEON is unsuitable here because
// arm64 NEON has no 64-bit integer multiply instruction.
func xxh64Sum(b []byte) uint64
