#pragma once
#include "pin.H"

#include "state.h"
#include "HiddenElements.h"
#include "helper.h"
#include "exceptionHandler.h"
#include "config.h"
#include "memory.h"

#include <set>

#define ADDR			0x40108F
#define PAGESIZE		4096
#define PATCH_SIZE		50
#define JMP_OPC_SIZE	2
#define ADDR_SIZE		4

typedef struct {
	UINT32 start;
	UINT32 fin;
	UINT32 ret;
	unsigned char patch[PATCH_SIZE];
} patch_struct;

VOID INS_InstrumentINS(INS ins);

VOID INS_patchRtdsc_exit(ADDRINT ip, CONTEXT *ctxt, ADDRINT cur_eip);
VOID INS_patchCpuid_entry(ADDRINT ip, CONTEXT *ctxt, ADDRINT cur_eip);
VOID INS_patchCpuid_exit(ADDRINT ip, CONTEXT *ctxt, ADDRINT cur_eip);
VOID INS_patchInt2d_entry(CONTEXT *ctx, THREADID tid, ADDRINT accessAddr);
VOID INS_patchIn_exit(CONTEXT *ctx);
VOID INS_AddInsStealth(INS ins);
BOOL INS_EnableInsStealth(std::string input, std::string *result);
BOOL INS_DisableInsStealth(std::string input, std::string *result);
