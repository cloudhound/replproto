#include "textflag.h"

// func xxh64Sum(b []byte) uint64
//
// xxh64 (seed=0) for arm64. uses scalar instructions with LDP for
// 16-byte loads. processes 32 bytes per main-loop iteration with
// 4 independent accumulators.
//
// register allocation:
//   R0  — data pointer (advances)
//   R1  — remaining length (decremented)
//   R2  — original length (preserved for h64 += len)
//   R3  — v1 accumulator
//   R4  — v2 accumulator
//   R5  — v3 accumulator
//   R6  — v4 accumulator
//   R7  — PRIME1 (0x9E3779B185EBCA87)
//   R8  — PRIME2 (0xC2B2AE3D27D4EB4F)
//   R9  — PRIME3 (0x165667B19E3779F9)
//   R10 — PRIME4 (0x85EBCA77C2B2AE63)
//   R11 — PRIME5 (0x27D4EB2F165667C5)
//   R12-R15 — load temps
//   R16 — h64 result accumulator
//   R17 — scratch for MUL intermediates
TEXT ·xxh64Sum(SB), NOSPLIT, $0-32
	MOVD	data_base+0(FP), R0
	MOVD	data_len+8(FP), R1
	MOVD	R1, R2

	// load constants
	MOVD	$0x9E3779B185EBCA87, R7
	MOVD	$0xC2B2AE3D27D4EB4F, R8
	MOVD	$0x165667B19E3779F9, R9
	MOVD	$0x85EBCA77C2B2AE63, R10
	MOVD	$0x27D4EB2F165667C5, R11

	CMP	$32, R1
	BLT	short

	// initialize accumulators (seed=0)
	ADD	R7, R8, R3		// v1 = PRIME1 + PRIME2
	MOVD	R8, R4			// v2 = PRIME2
	MOVD	$0, R5			// v3 = 0
	MOVD	$0, R6			// v4 = 0
	SUB	R7, R6, R6		// v4 = 0 - PRIME1

loop32:
	// load 32 bytes via two load-pairs
	LDP	(R0), (R12, R13)
	LDP	16(R0), (R14, R15)
	ADD	$32, R0
	SUB	$32, R1

	// round(v1, R12): v1 = rotl(v1 + R12*PRIME2, 31) * PRIME1
	MUL	R12, R8, R17
	ADD	R17, R3, R3
	ROR	$33, R3, R3
	MUL	R7, R3, R3

	// round(v2, R13)
	MUL	R13, R8, R17
	ADD	R17, R4, R4
	ROR	$33, R4, R4
	MUL	R7, R4, R4

	// round(v3, R14)
	MUL	R14, R8, R17
	ADD	R17, R5, R5
	ROR	$33, R5, R5
	MUL	R7, R5, R5

	// round(v4, R15)
	MUL	R15, R8, R17
	ADD	R17, R6, R6
	ROR	$33, R6, R6
	MUL	R7, R6, R6

	CMP	$32, R1
	BGE	loop32

	// merge: h64 = rotl(v1,1) + rotl(v2,7) + rotl(v3,12) + rotl(v4,18)
	ROR	$63, R3, R16		// rotl(v1, 1)
	ROR	$57, R4, R12		// rotl(v2, 7)
	ADD	R12, R16, R16
	ROR	$52, R5, R12		// rotl(v3, 12)
	ADD	R12, R16, R16
	ROR	$46, R6, R12		// rotl(v4, 18)
	ADD	R12, R16, R16

	// mergeRound(h64, v1): v=round(0,v); h^=v; h=h*PRIME1+PRIME4
	MUL	R8, R3, R3
	ROR	$33, R3, R3
	MUL	R7, R3, R3
	EOR	R3, R16, R16
	MUL	R7, R16, R17
	ADD	R10, R17, R16

	// mergeRound(h64, v2)
	MUL	R8, R4, R4
	ROR	$33, R4, R4
	MUL	R7, R4, R4
	EOR	R4, R16, R16
	MUL	R7, R16, R17
	ADD	R10, R17, R16

	// mergeRound(h64, v3)
	MUL	R8, R5, R5
	ROR	$33, R5, R5
	MUL	R7, R5, R5
	EOR	R5, R16, R16
	MUL	R7, R16, R17
	ADD	R10, R17, R16

	// mergeRound(h64, v4)
	MUL	R8, R6, R6
	ROR	$33, R6, R6
	MUL	R7, R6, R6
	EOR	R6, R16, R16
	MUL	R7, R16, R17
	ADD	R10, R17, R16

	B	tail

short:
	// length < 32: h64 = PRIME5
	MOVD	R11, R16

tail:
	// h64 += original length
	ADD	R2, R16, R16

	// process remaining 8-byte chunks
tail8:
	CMP	$8, R1
	BLT	tail4
	MOVD	(R0), R12
	ADD	$8, R0
	SUB	$8, R1
	// round(0, R12)
	MUL	R8, R12, R12
	ROR	$33, R12, R12
	MUL	R7, R12, R12
	EOR	R12, R16, R16
	ROR	$37, R16, R16		// rotl(h64, 27)
	MUL	R7, R16, R17		// h64*PRIME1
	ADD	R10, R17, R16		// + PRIME4
	B	tail8

tail4:
	CMP	$4, R1
	BLT	tail1
	MOVWU	(R0), R12		// 32-bit zero-extended
	ADD	$4, R0
	SUB	$4, R1
	MUL	R7, R12, R12		// input * PRIME1
	EOR	R12, R16, R16		// h64 ^= ...
	ROR	$41, R16, R16		// rotl(h64, 23)
	MUL	R8, R16, R17		// h64*PRIME2
	ADD	R9, R17, R16		// + PRIME3

tail1:
	CBZ	R1, finalize

tail1_loop:
	MOVBU	(R0), R12
	ADD	$1, R0
	SUB	$1, R1
	MUL	R11, R12, R12		// input * PRIME5
	EOR	R12, R16, R16		// h64 ^= ...
	ROR	$53, R16, R16		// rotl(h64, 11)
	MUL	R7, R16, R16		// h64 *= PRIME1
	CBNZ	R1, tail1_loop

finalize:
	// avalanche
	LSR	$33, R16, R12
	EOR	R12, R16, R16		// h64 ^= h64 >> 33
	MUL	R8, R16, R16		// h64 *= PRIME2
	LSR	$29, R16, R12
	EOR	R12, R16, R16		// h64 ^= h64 >> 29
	MUL	R9, R16, R16		// h64 *= PRIME3
	LSR	$32, R16, R12
	EOR	R12, R16, R16		// h64 ^= h64 >> 32

	MOVD	R16, ret+24(FP)
	RET
