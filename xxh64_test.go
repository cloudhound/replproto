package replproto

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"

	xxhash "github.com/cespare/xxhash/v2"
)

// TestXXH64SumEmpty verifies the well-known xxh64 hash of empty input (seed=0)
func TestXXH64SumEmpty(t *testing.T) {
	got := xxh64Sum(nil)
	want := uint64(0xEF46DB3751D8E999)
	if got != want {
		t.Errorf("xxh64Sum(nil): got 0x%016X, want 0x%016X", got, want)
	}

	got = xxh64Sum([]byte{})
	if got != want {
		t.Errorf("xxh64Sum([]byte{}): got 0x%016X, want 0x%016X", got, want)
	}
}

// TestXXH64SumAgainstReference compares our implementation against
// the cespare/xxhash library across many sizes. This covers every
// code path: short (<32), main loop (32-byte stripes), and all tail
// sizes (8-byte, 4-byte, and 1-byte chunks).
func TestXXH64SumAgainstReference(t *testing.T) {
	sizes := []int{
		0, 1, 2, 3, 4, 5, 6, 7, 8,
		9, 10, 15, 16, 17, 23, 24, 25,
		31, 32, 33, 63, 64, 65, 95, 96, 97,
		127, 128, 129, 255, 256, 257,
		511, 512, 1023, 1024,
		4095, 4096, 4097,
		65535, 65536,
	}

	for _, sz := range sizes {
		t.Run(fmt.Sprintf("random_%d", sz), func(t *testing.T) {
			data := make([]byte, sz)
			if sz > 0 {
				rand.Read(data)
			}
			got := xxh64Sum(data)
			want := xxhash.Sum64(data)
			if got != want {
				t.Errorf("xxh64Sum (len=%d): got 0x%016X, want 0x%016X", sz, got, want)
			}
		})
	}
}

// TestXXH64SumAllZeros verifies zero-filled inputs of various sizes
func TestXXH64SumAllZeros(t *testing.T) {
	for _, sz := range []int{1, 4, 7, 8, 16, 31, 32, 33, 64, 128, 4096} {
		t.Run(fmt.Sprintf("zeros_%d", sz), func(t *testing.T) {
			data := make([]byte, sz)
			got := xxh64Sum(data)
			want := xxhash.Sum64(data)
			if got != want {
				t.Errorf("got 0x%016X, want 0x%016X", got, want)
			}
		})
	}
}

// TestXXH64SumAllOnes verifies 0xFF-filled inputs
func TestXXH64SumAllOnes(t *testing.T) {
	for _, sz := range []int{1, 4, 7, 8, 16, 31, 32, 33, 64, 128, 4096} {
		t.Run(fmt.Sprintf("ones_%d", sz), func(t *testing.T) {
			data := bytes.Repeat([]byte{0xFF}, sz)
			got := xxh64Sum(data)
			want := xxhash.Sum64(data)
			if got != want {
				t.Errorf("got 0x%016X, want 0x%016X", got, want)
			}
		})
	}
}

// TestXXH64SumSequential verifies sequential byte patterns
func TestXXH64SumSequential(t *testing.T) {
	for _, sz := range []int{1, 8, 16, 31, 32, 33, 64, 100, 128, 256} {
		t.Run(fmt.Sprintf("seq_%d", sz), func(t *testing.T) {
			data := make([]byte, sz)
			for i := range data {
				data[i] = byte(i)
			}
			got := xxh64Sum(data)
			want := xxhash.Sum64(data)
			if got != want {
				t.Errorf("got 0x%016X, want 0x%016X", got, want)
			}
		})
	}
}

// TestXXH64SumSingleByte verifies all 256 possible single-byte inputs
func TestXXH64SumSingleByte(t *testing.T) {
	for b := 0; b < 256; b++ {
		data := []byte{byte(b)}
		got := xxh64Sum(data)
		want := xxhash.Sum64(data)
		if got != want {
			t.Errorf("byte 0x%02X: got 0x%016X, want 0x%016X", b, got, want)
		}
	}
}

// TestXXH64SumTailPaths exercises specific tail sizes that hit
// different combinations of the 8-byte, 4-byte, and 1-byte paths.
// After the 32-byte main loop, remaining bytes = N % 32:
//   0  → no tail
//   8  → one 8-byte chunk
//   12 → one 8 + one 4
//   15 → one 8 + one 4 + three 1-byte
//   24 → three 8-byte chunks
//   28 → three 8 + one 4
//   31 → three 8 + one 4 + three 1-byte
func TestXXH64SumTailPaths(t *testing.T) {
	// base = 64 (two full 32-byte stripes) + various remainders
	remainders := []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 12, 15, 16, 20, 24, 28, 31}
	for _, rem := range remainders {
		sz := 64 + rem
		t.Run(fmt.Sprintf("tail_%d", rem), func(t *testing.T) {
			data := make([]byte, sz)
			rand.Read(data)
			got := xxh64Sum(data)
			want := xxhash.Sum64(data)
			if got != want {
				t.Errorf("size=%d (tail=%d): got 0x%016X, want 0x%016X", sz, rem, got, want)
			}
		})
	}
}

// TestXXH64SumExactMultiples verifies inputs that are exact multiples
// of the 32-byte stripe size (no tail processing needed)
func TestXXH64SumExactMultiples(t *testing.T) {
	for _, n := range []int{32, 64, 96, 128, 256, 1024} {
		t.Run(fmt.Sprintf("exact_%d", n), func(t *testing.T) {
			data := make([]byte, n)
			rand.Read(data)
			got := xxh64Sum(data)
			want := xxhash.Sum64(data)
			if got != want {
				t.Errorf("got 0x%016X, want 0x%016X", got, want)
			}
		})
	}
}

// TestXXH64SumRepeatedCalls verifies determinism across multiple calls
func TestXXH64SumRepeatedCalls(t *testing.T) {
	data := make([]byte, 4096)
	rand.Read(data)

	first := xxh64Sum(data)
	for i := 0; i < 100; i++ {
		got := xxh64Sum(data)
		if got != first {
			t.Fatalf("call %d: got 0x%016X, want 0x%016X", i, got, first)
		}
	}
}

// TestXXH64SumLargeInput verifies correctness on a 1 MiB block
func TestXXH64SumLargeInput(t *testing.T) {
	data := make([]byte, 1<<20)
	rand.Read(data)
	got := xxh64Sum(data)
	want := xxhash.Sum64(data)
	if got != want {
		t.Errorf("1MiB: got 0x%016X, want 0x%016X", got, want)
	}
}

// TestBlockChecksumUsesXXH64 verifies BlockChecksum matches xxh64
func TestBlockChecksumUsesXXH64(t *testing.T) {
	data := make([]byte, 4096)
	rand.Read(data)
	cs := BlockChecksum(data)
	want := xxhash.Sum64(data)
	// BlockChecksum returns big-endian encoding of the hash
	got := uint64(cs[0])<<56 | uint64(cs[1])<<48 | uint64(cs[2])<<40 | uint64(cs[3])<<32 |
		uint64(cs[4])<<24 | uint64(cs[5])<<16 | uint64(cs[6])<<8 | uint64(cs[7])
	if got != want {
		t.Errorf("BlockChecksum: got 0x%016X, want 0x%016X", got, want)
	}
}

func BenchmarkXXH64Sum(b *testing.B) {
	for _, size := range []int{4, 16, 32, 64, 128, 256, 1024, 4096, 65536, 1 << 20} {
		b.Run(fmt.Sprintf("size=%d", size), func(b *testing.B) {
			data := make([]byte, size)
			rand.Read(data)
			b.SetBytes(int64(size))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				xxh64Sum(data)
			}
		})
	}
}

func BenchmarkXXH64SumReference(b *testing.B) {
	for _, size := range []int{4, 16, 32, 64, 128, 256, 1024, 4096, 65536, 1 << 20} {
		b.Run(fmt.Sprintf("size=%d", size), func(b *testing.B) {
			data := make([]byte, size)
			rand.Read(data)
			b.SetBytes(int64(size))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				xxhash.Sum64(data)
			}
		})
	}
}
