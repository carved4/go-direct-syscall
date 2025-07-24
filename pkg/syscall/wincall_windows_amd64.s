#include "go_asm.h"
#include "textflag.h"

#define const_maxArgs 16

// Offsets into Thread Environment Block (pointer in GS)
#define TEB_TlsSlots 0x1480
#define TEB_ArbitraryPtr 0x28

// func wincall(libcall *libcall)
TEXT ·wincall(SB),NOSPLIT,$0
    MOVQ libcall+0(FP), CX
    CALL ·do_call_internal(SB)
    RET

TEXT ·do_call(SB),NOSPLIT,$0
	MOVQ	AX, CX
	JMP	·do_call_internal(SB)

// void ·do_call_internal(void *c);
TEXT ·do_call_internal(SB),NOSPLIT,$16
	MOVQ	SP, AX
	ANDQ	$~15, SP	// alignment as per Windows requirement
	MOVQ	AX, 8(SP)
	MOVQ	CX, 0(SP)	// asmcgocall will put first argument into CX.

	MOVQ	libcall_fn(CX), R11  // Store function address in R11 (safe register)
	MOVQ	libcall_args(CX), SI
	MOVQ	libcall_n(CX), CX

	// SetLastError(0).
	MOVQ	0x30(GS), DI
	MOVL	$0, 0x68(DI)

	SUBQ	$(const_maxArgs*8), SP	// room for args

	// Copy arguments to our stack space to prevent GC issues
	MOVQ	CX, R12		// Save arg count
	MOVQ	SP, DI		// Destination for copy

	// Manual copy loop instead of REP; MOVSQ
	TESTQ	CX, CX
	JZ	_copy_done
	_copy_loop:
		MOVQ	(SI), AX	// Load from source
		MOVQ	AX, (DI)	// Store to destination
		ADDQ	$8, SI		// Advance source
		ADDQ	$8, DI		// Advance destination
		DECQ	CX		// Decrement counter
		JNZ	_copy_loop
	_copy_done:

	MOVQ	SP, SI		// Use copied args
	MOVQ	R12, CX		// Restore arg count

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

	// SI already contains the args pointer from line 28, don't overwrite it!
	// MOVQ	SP, SI  // <-- REMOVE THIS LINE

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
	SUBQ $32, SP  // Allocate shadow space
	CALL	R11   // Call the preserved function address in R11
	ADDQ $32, SP  // Clean up shadow space

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
    