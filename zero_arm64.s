#include "textflag.h"

// func isZeroNEON(data []byte) bool
// checks if all bytes are zero using ARM64 NEON 128-bit operations.
// main loop processes 64 bytes (4×V register) per iteration, then
// 16-byte cleanup, then byte-by-byte tail.
TEXT ·isZeroNEON(SB), NOSPLIT, $0-25
	MOVD	data_base+0(FP), R0	// base pointer
	MOVD	data_len+8(FP), R1	// length

	// 64-byte unrolled main loop
	CMP	$64, R1
	BLT	loop16

loop64:
	VLD1.P	64(R0), [V0.B16, V1.B16, V2.B16, V3.B16]
	VORR	V0.B16, V1.B16, V4.B16
	VORR	V2.B16, V3.B16, V5.B16
	VORR	V4.B16, V5.B16, V4.B16

	// fold 128 bits to 64: shift high half down, OR with low half
	VEXT	$8, V4.B16, V4.B16, V5.B16
	VORR	V4.B8, V5.B8, V4.B8
	FMOVD	F4, R2
	CBNZ	R2, nonzero

	SUB	$64, R1
	CMP	$64, R1
	BGE	loop64

loop16:
	CMP	$16, R1
	BLT	tail
	VLD1.P	16(R0), [V0.B16]

	// fold 128 bits to 64
	VEXT	$8, V0.B16, V0.B16, V1.B16
	VORR	V0.B8, V1.B8, V0.B8
	FMOVD	F0, R2
	CBNZ	R2, nonzero

	SUB	$16, R1
	B	loop16

tail:
	CBZ	R1, is_zero

tail_loop:
	MOVBU.P	1(R0), R2
	CBNZ	R2, nonzero
	SUB	$1, R1
	CBNZ	R1, tail_loop

is_zero:
	MOVD	$1, R0
	MOVB	R0, ret+24(FP)
	RET

nonzero:
	MOVD	$0, R0
	MOVB	R0, ret+24(FP)
	RET
