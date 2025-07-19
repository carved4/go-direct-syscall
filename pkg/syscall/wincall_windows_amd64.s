#include "go_asm.h"
#include "textflag.h"

#define const_maxArgs 16

// Offsets into Thread Environment Block (pointer in GS)
#define TEB_TlsSlots 0x1480
#define TEB_ArbitraryPtr 0x28

TEXT ·do_call(SB),NOSPLIT,$0
	MOVQ	AX, CX
	JMP	·do_call_internal(SB)

// void ·do_call_internal(void *c);
TEXT ·do_call_internal(SB),NOSPLIT,$16
	MOVQ	SP, AX
	ANDQ	$~15, SP	// alignment as per Windows requirement
	MOVQ	AX, 8(SP)
	MOVQ	CX, 0(SP)	// asmcgocall will put first argument into CX.

	MOVQ	libcall_fn(CX), AX
	MOVQ	libcall_args(CX), SI
	MOVQ	libcall_n(CX), CX

	// SetLastError(0).
	MOVQ	0x30(GS), DI
	MOVL	$0, 0x68(DI)

	SUBQ	$(const_maxArgs*8), SP	// room for args

	// Fast version, do not store args on the stack.
	CMPL	CX, $0;	JE	_0args
	CMPL	CX, $1;	JE	_1args
	CMPL	CX, $2;	JE	_2args
	CMPL	CX, $3;	JE	_3args
	CMPL	CX, $4;	JE	_4args

	// Check we have enough room for args.
	CMPL	CX, $const_maxArgs
	JLE	2(PC)
	INT	$3			// not enough room -> crash

	// Copy args to the stack.
	MOVQ	SP, DI
	CLD
	REP; MOVSQ
	MOVQ	SP, SI

	// Load first 4 args into correspondent registers.
	// Floating point arguments are passed in the XMM
	// registers. Set them here in case any of the arguments
	// are floating point values. For details see
	//	https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention?view=msvc-170
_4args:
	MOVQ	24(SI), R9
	MOVQ	R9, X3
_3args:
	MOVQ	16(SI), R8
	MOVQ	R8, X2
_2args:
	MOVQ	8(SI), DX
	MOVQ	DX, X1
_1args:
	MOVQ	0(SI), CX
	MOVQ	CX, X0
_0args:

	// Call stdcall function.
	CALL	AX

	ADDQ	$(const_maxArgs*8), SP

	// Return result.
	MOVQ	0(SP), CX
	MOVQ	8(SP), SP
	MOVQ	AX, libcall_r1(CX)
	// Floating point return values are returned in XMM0. Setting r2 to this
	// value in case this call returned a floating point value. For details,
	// see https://docs.microsoft.com/en-us/cpp/build/x64-calling-convention
	MOVQ    X0, libcall_r2(CX)

	// GetLastError().
	MOVQ	0x30(GS), DI
	MOVL	0x68(DI), AX
	MOVQ	AX, libcall_err(CX)

	RET

// faster get/set last error
TEXT ·getlasterror(SB),NOSPLIT,$0
	MOVQ	0x30(GS), AX
	MOVL	0x68(AX), AX
	MOVL	AX, ret+0(FP)
	RET
    