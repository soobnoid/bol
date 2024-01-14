#define VC_EXTRALEAN
#define WIN32_LEAN_AND_MEAN
#pragma once

#include <Windows.h>
#include <Zydis/Zydis.h>

// counting a call as a "jmp" because it takes
// an immediate and changes the instruction pointer.

// JCXZ not included since it is upgraded to JECXZ
// in 64-bit mode.

ZydisMnemonic jmps [] = 
{
	ZYDIS_MNEMONIC_JMP,
    ZYDIS_MNEMONIC_JNB,
	ZYDIS_MNEMONIC_JNBE,
	ZYDIS_MNEMONIC_JBE,
	ZYDIS_MNEMONIC_JB,
	ZYDIS_MNEMONIC_JECXZ,
	ZYDIS_MNEMONIC_JZ,
	ZYDIS_MNEMONIC_JNL,
	ZYDIS_MNEMONIC_JNLE,
	ZYDIS_MNEMONIC_JLE,
	ZYDIS_MNEMONIC_JL,
	ZYDIS_MNEMONIC_JNZ,
	ZYDIS_MNEMONIC_JNO,
	ZYDIS_MNEMONIC_JNP,
	ZYDIS_MNEMONIC_JNS,
	ZYDIS_MNEMONIC_JO,
	ZYDIS_MNEMONIC_JP,
	ZYDIS_MNEMONIC_JRCXZ,
	ZYDIS_MNEMONIC_JS,
    ZYDIS_MNEMONIC_CALL
};

ZydisMnemonic branchingJmps [] =
{
	ZYDIS_MNEMONIC_JNB,
	ZYDIS_MNEMONIC_JNBE,
	ZYDIS_MNEMONIC_JBE,
	ZYDIS_MNEMONIC_JB,
	ZYDIS_MNEMONIC_JECXZ,
	ZYDIS_MNEMONIC_JZ,
	ZYDIS_MNEMONIC_JNL,
	ZYDIS_MNEMONIC_JNLE,
	ZYDIS_MNEMONIC_JLE,
	ZYDIS_MNEMONIC_JL,
	ZYDIS_MNEMONIC_JNZ,
	ZYDIS_MNEMONIC_JNO,
	ZYDIS_MNEMONIC_JNP,
	ZYDIS_MNEMONIC_JNS,
	ZYDIS_MNEMONIC_JO,
	ZYDIS_MNEMONIC_JP,
	ZYDIS_MNEMONIC_JRCXZ,
	ZYDIS_MNEMONIC_JS
};

bool jmpTaken(ZydisMnemonic jumpInsn, PCONTEXT ctx) 
{
	#define isCarry(eflags)       (((eflags) & 0x1) != 0)
	#define isParity(eflags)      (((eflags) & 0x4) != 0)
	#define isAdjust(eflags)      (((eflags) & 0x10) != 0)
	#define isZero(eflags)        (((eflags) & 0x40) != 0)
	#define isSign(eflags)        (((eflags) & 0x80) != 0)
	#define isTrap(eflags)        (((eflags) & 0x100) != 0)
	#define isInterrupt(eflags)   (((eflags) & 0x200) != 0)
	#define isDirection(eflags)   (((eflags) & 0x400) != 0)
	#define isOverflow(eflags)    (((eflags) & 0x800) != 0)
	#define isNestedTask(eflags)  (((eflags) & 0x4000) != 0)
	#define isResume(eflags)      (((eflags) & 0x10000) != 0)
	#define isVirtual8086(eflags) (((eflags) & 0x20000) != 0)
	#define isAlignmentCheck(eflags) (((eflags) & 0x40000) != 0)
	#define isVirtualInterrupt(eflags) (((eflags) & 0x80000) != 0)
	#define isVirtualInterruptPending(eflags) (((eflags) & 0x100000) != 0)
	#define isIdentification(eflags) (((eflags) & 0x200000) != 0)

	UINT32 eflags = ctx->EFlags;

    switch (jumpInsn) 
	{
        case ZYDIS_MNEMONIC_JO:
			return isOverflow(eflags);

		case ZYDIS_MNEMONIC_JNO:
			return !isOverflow(eflags);
		
		case ZYDIS_MNEMONIC_JS:
			return isSign(eflags);
		
		case ZYDIS_MNEMONIC_JNS:
			return !isSign(eflags);
		
		case ZYDIS_MNEMONIC_JZ:
			return isZero(eflags);

		case ZYDIS_MNEMONIC_JNZ:
			return !isZero(eflags);

		case ZYDIS_MNEMONIC_JB:
			return isCarry(eflags);
		
		case ZYDIS_MNEMONIC_JNB:
			return !isCarry(eflags);
		
		case ZYDIS_MNEMONIC_JBE:
			return isCarry(eflags) || isZero(eflags);

		case ZYDIS_MNEMONIC_JNBE:
			return !isCarry(eflags) && !isZero(eflags);
		
		case ZYDIS_MNEMONIC_JL:
			return isSign(eflags) != isOverflow(eflags);
		
		case ZYDIS_MNEMONIC_JNL:
			return isSign(eflags) == isOverflow(eflags);

		case ZYDIS_MNEMONIC_JLE:
			return isZero(eflags) || isSign(eflags) != isOverflow(eflags);
		
		case ZYDIS_MNEMONIC_JNLE:
			return !isZero(eflags) && isSign(eflags) == isOverflow(eflags);

		case ZYDIS_MNEMONIC_JP:
			return isParity(eflags);

		case ZYDIS_MNEMONIC_JNP:
			return !isParity(eflags);

		case ZYDIS_MNEMONIC_JECXZ:
			return ((UINT32) ctx->Rcx) == 0;
		
		case ZYDIS_MNEMONIC_JRCXZ:
			return ctx->Rdx == 0;
    }
}