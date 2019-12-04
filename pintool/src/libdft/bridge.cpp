#include "pin.H"

#include <iostream>

#include "libdft_api.h"
#include "tagmap.h"
#include "bridge.h" // also for thread_ctx_ptr

// DCD: assert_* methods have been borrowed from libdft-dta.c

#define TTINFO(field) thread_ctx->ttinfo.field

// borrowed from libdft_core.cpp
#define RTAG thread_ctx->vcpu.gpr
#define R32TAG(RIDX) \
    {RTAG[(RIDX)][0], RTAG[(RIDX)][1], RTAG[(RIDX)][2], RTAG[(RIDX)][3]}

//thread_ctx_t *thread_ctx = (thread_ctx_t *) PIN_GetContextReg(ctx, thread_ctx_ptr);
void addTaintRegister(thread_ctx_t *thread_ctx, int gpr, tag_t tags[], bool reset) {
	tag_t src_tag[] = R32TAG(gpr);
	for (UINT32 i = 0; i < 4; ++i) {
		tag_t t = tags[i];
		if (!reset) t |= src_tag[i];
		RTAG[gpr][i] = t;
	}
}

void clearTaintRegister(thread_ctx_t *thread_ctx, int gpr) {
	memset(RTAG[gpr], 0, sizeof(RTAG[gpr]));
}

void getRegisterTaints(thread_ctx_t *thread_ctx, int gpr, tag_t *tags) {
	memcpy(tags, RTAG[gpr], sizeof(RTAG[gpr]));
}

void getMemoryTaints(ADDRINT addr, tag_t* tags, UINT32 size) {
	for (UINT32 i = 0; i < size; ++i) {
		tags[i] = tagmap_getb(addr + i);
	}
}

void addTaintMemory(ADDRINT addr, UINT32 size, tag_t tag, bool reset) {
	ASSERT(sizeof(ADDRINT) == sizeof(UINT32), "64-bit mode not supported yet");
	std::cerr << "Tainting addresses " << addr << " to " << addr + size << std::endl;
	for (UINT32 i = 0; i < size; ++i) {
		tag_t t = tag;
		if (!reset) t |= tagmap_getb(addr + i);
		tagmap_setb_with_tag(addr + i, t);
	}

	//tag_t x = tagmap_getl(addr); // TODO check why we have this leftover
}

void clearTaintMemory(ADDRINT addr, UINT32 size) {
	ASSERT(sizeof(ADDRINT) == sizeof(UINT32), "64-bit mode not supported yet");
	for (UINT32 i = 0; i < size; ++i) {
		tag_t t = 0;
		tagmap_setb_with_tag(addr + i, t);
	}
}

/*
* DTA/DFT alert
*
* @ins:	address of the offending instruction
* @bt:		address of the branch target
*/
static void PIN_FAST_ANALYSIS_CALL alert(thread_ctx_t *thread_ctx, ADDRINT addr, INS i) {
	/* log file */
	if (TTINFO(tainted)) {
#if 0
		if (Process::getInstance()->isInsideMainIMG(addr)) goto END;
		char buf[512];
		sprintf(buf, "Tainted instruction: 0x%08x [%d] %s\n",
			addr, (int)TTINFO(tainted), INS_Disassemble(i).c_str());
		//fprintf(stderr, "%s", buf);		
		FILE *logFile = fopen(TTINFO(logname), "a");
		if (logFile) {
			fprintf(logFile, "%s", buf);
			fclose(logFile);
		}
	}
END:
#else
}
#endif
	TTINFO(tainted) = 0;
}

static void PIN_FAST_ANALYSIS_CALL
assert_reg32(thread_ctx_t *thread_ctx, UINT32 reg) {
	// DCD we use uint8_t as LIBDFT_TAG_TYPE
	TTINFO(tainted) |= thread_ctx->vcpu.gpr[reg][0] |
		thread_ctx->vcpu.gpr[reg][1] |
		thread_ctx->vcpu.gpr[reg][2] |
		thread_ctx->vcpu.gpr[reg][3];
	//std::cerr << "REG32" << std::endl;
}

static void PIN_FAST_ANALYSIS_CALL
assert_reg16(thread_ctx_t *thread_ctx, UINT32 reg) {
	// DCD we use uint8_t as LIBDFT_TAG_TYPE
	TTINFO(tainted) |= thread_ctx->vcpu.gpr[reg][0] |
		thread_ctx->vcpu.gpr[reg][1];
	//std::cerr << "REG16" << std::endl;
}

static void PIN_FAST_ANALYSIS_CALL
assert_reg8(thread_ctx_t *thread_ctx, UINT32 reg) { // DCD TODO
													// DCD we use uint8_t as LIBDFT_TAG_TYPE
	TTINFO(tainted) |= thread_ctx->vcpu.gpr[reg][0];
	//std::cerr << "REG8" << std::endl;
}

static void PIN_FAST_ANALYSIS_CALL
assert_mem256(thread_ctx_t *thread_ctx, UINT32 addr) {
	TTINFO(tainted) |= tagmap_getl(addr) | tagmap_getl(addr + 4) |
		tagmap_getl(addr + 8) | tagmap_getl(addr + 12) |
		tagmap_getl(addr + 16) | tagmap_getl(addr + 20) |
		tagmap_getl(addr + 24) | tagmap_getl(addr + 28);
	//std::cerr << "MEM256" << std::endl;
}

static void PIN_FAST_ANALYSIS_CALL
assert_mem128(thread_ctx_t *thread_ctx, UINT32 addr) {
	TTINFO(tainted) |= tagmap_getl(addr) | tagmap_getl(addr + 4) |
		tagmap_getl(addr + 8) | tagmap_getl(addr + 12);
	//std::cerr << "MEM128" << std::endl;
}

static void PIN_FAST_ANALYSIS_CALL
assert_mem64(thread_ctx_t *thread_ctx, UINT32 addr) {
	TTINFO(tainted) |= tagmap_getl(addr) | tagmap_getl(addr + 4);
	//std::cerr << "MEM64" << std::endl;
}

static void PIN_FAST_ANALYSIS_CALL
assert_mem32(thread_ctx_t *thread_ctx, UINT32 addr) {
	TTINFO(tainted) |= tagmap_getl(addr);
	//std::cerr << "MEM32" << std::endl;
}

static void PIN_FAST_ANALYSIS_CALL
assert_mem16(thread_ctx_t *thread_ctx, UINT32 addr) {
	TTINFO(tainted) |= tagmap_getw(addr);
	//std::cerr << "MEM16" << std::endl;
}

static void PIN_FAST_ANALYSIS_CALL
assert_mem8(thread_ctx_t *thread_ctx, UINT32 addr) {
	TTINFO(tainted) |= tagmap_getb(addr);
	//std::cerr << "MEM8" << std::endl;
}

static void PIN_FAST_ANALYSIS_CALL
assert_mem_generic(thread_ctx_t *thread_ctx, UINT32 addr, UINT32 size) {
	ASSERT(size % 4 == 0, "Unaligned memory access?");
	for (UINT32 i = 0; i < size / 4; i++)
		TTINFO(tainted) |= tagmap_getl(addr + 4 * i);
	//std::cerr << "MEM" << size*8 << std::endl;
}

void instrumentForTaintCheck(INS ins, void*) {
	if (INS_MaxNumRRegs(ins) == 0) return; // the instruction does not have read operands

	UINT32 operands = INS_OperandCount(ins);

	// iterate over registers
	for (UINT32 opIdx = 0; opIdx < operands; ++opIdx) {
		if (INS_OperandIsReg(ins, opIdx) && INS_OperandRead(ins, opIdx)) {
			REG reg = INS_OperandReg(ins, opIdx);
			if (REG_is_gr32(reg)) {
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)assert_reg32,
					IARG_FAST_ANALYSIS_CALL,
					IARG_REG_VALUE,
					thread_ctx_ptr,
					IARG_UINT32,
					REG32_INDX(reg),
					IARG_END);
			}
			else if (REG_is_gr16(reg)) {
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)assert_reg16,
					IARG_FAST_ANALYSIS_CALL,
					IARG_REG_VALUE,
					thread_ctx_ptr,
					IARG_UINT32,
					REG16_INDX(reg),
					IARG_END);
			}
			else if (REG_is_gr8(reg)) {
				// DCD what about this? no sign of it in libdft-dta
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)assert_reg8,
					IARG_FAST_ANALYSIS_CALL,
					IARG_REG_VALUE,
					thread_ctx_ptr,
					IARG_UINT32,
					REG8_INDX(reg),
					IARG_END);
			}
		}
	}

	if (!INS_IsMemoryRead(ins)) goto end;

	UINT32 memOperands = INS_MemoryOperandCount(ins);
	for (UINT32 memOpIdx = 0; memOpIdx < memOperands; memOpIdx++) {
		if (INS_MemoryOperandIsRead(ins, memOpIdx)) {
			USIZE opSize = INS_MemoryOperandSize(ins, memOpIdx);
			AFUNPTR assert_mem = NULL;
			switch (opSize) {
			case 32:
				assert_mem = (AFUNPTR)assert_mem256;
				break;
			case 16:
				assert_mem = (AFUNPTR)assert_mem128;
				break;
			case 8:
				assert_mem = (AFUNPTR)assert_mem64;
				break;
			case 4:
				assert_mem = (AFUNPTR)assert_mem32;
				break;
			case 2:
				assert_mem = (AFUNPTR)assert_mem16;
				break;
			case 1:
				assert_mem = (AFUNPTR)assert_mem8;
				break;
			default:
				std::cerr << "Unknown memory read size: " << opSize << std::endl;
			}
			if (assert_mem != NULL) {
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)assert_mem,
					IARG_FAST_ANALYSIS_CALL,
					IARG_REG_VALUE,
					thread_ctx_ptr,
					IARG_MEMORYOP_EA,
					memOpIdx,
					IARG_END);
			}
			else {
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)assert_mem_generic,
					IARG_FAST_ANALYSIS_CALL,
					IARG_REG_VALUE,
					thread_ctx_ptr,
					IARG_MEMORYOP_EA,
					memOpIdx,
					IARG_UINT32,
					opSize,
					IARG_END);
			}
		}
	}

end:
	// check taint before the instruction is executed
	// TODO: it would be cool to have just one InsertIfCall and use an InsertThenCall here
	INS_InsertCall(ins,
		IPOINT_BEFORE,
		(AFUNPTR)alert,
		IARG_FAST_ANALYSIS_CALL,
		IARG_REG_VALUE,
		thread_ctx_ptr,
		IARG_INST_PTR,
		IARG_PTR,
		ins,
		IARG_END);
	return;
}
