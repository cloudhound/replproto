#include "textflag.h"

// func cpuidHasAVX2() bool
// Checks OSXSAVE + AVX YMM state + AVX2 instruction support.
TEXT ·cpuidHasAVX2(SB), NOSPLIT, $0-1
	// Step 1: Check OSXSAVE support (CPUID leaf 1, ECX bit 27).
	// OSXSAVE indicates the OS uses XSAVE/XRSTOR for extended state.
	MOVL	$1, AX
	XORL	CX, CX
	CPUID
	TESTL	$(1<<27), CX
	JZ	no_avx2

	// Step 2: Verify OS saves YMM state via XCR0 bits 1 (SSE) and 2 (AVX).
	XORL	CX, CX
	XGETBV
	ANDL	$6, AX
	CMPL	AX, $6
	JNE	no_avx2

	// Step 3: Check AVX2 (CPUID leaf 7, subleaf 0, EBX bit 5).
	MOVL	$7, AX
	XORL	CX, CX
	CPUID
	TESTL	$(1<<5), BX
	JZ	no_avx2

	MOVB	$1, ret+0(FP)
	RET

no_avx2:
	MOVB	$0, ret+0(FP)
	RET

// func isZeroAVX2(data []byte) bool
// Checks if all bytes are zero using AVX2 256-bit operations.
// Main loop processes 128 bytes (4×YMM) per iteration, then 32-byte
// cleanup, then byte-by-byte tail.
TEXT ·isZeroAVX2(SB), NOSPLIT, $0-25
	MOVQ	data_base+0(FP), SI
	MOVQ	data_len+8(FP), CX

	// 128-byte unrolled main loop
	CMPQ	CX, $128
	JB	loop32

loop128:
	VMOVDQU	0(SI), Y0
	VMOVDQU	32(SI), Y1
	VMOVDQU	64(SI), Y2
	VMOVDQU	96(SI), Y3
	VPOR	Y0, Y1, Y0
	VPOR	Y2, Y3, Y2
	VPOR	Y0, Y2, Y0
	VPTEST	Y0, Y0
	JNZ	nonzero
	ADDQ	$128, SI
	SUBQ	$128, CX
	CMPQ	CX, $128
	JAE	loop128

loop32:
	CMPQ	CX, $32
	JB	tail
	VMOVDQU	(SI), Y0
	VPTEST	Y0, Y0
	JNZ	nonzero
	ADDQ	$32, SI
	SUBQ	$32, CX
	JMP	loop32

tail:
	VZEROUPPER
	TESTQ	CX, CX
	JZ	is_zero

tail_loop:
	CMPB	(SI), $0
	JNE	ret_nonzero
	INCQ	SI
	DECQ	CX
	JNZ	tail_loop

is_zero:
	MOVB	$1, ret+24(FP)
	RET

nonzero:
	VZEROUPPER
ret_nonzero:
	MOVB	$0, ret+24(FP)
	RET
