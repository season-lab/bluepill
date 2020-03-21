#include "ins.h"
#include "winheaders.h"
#include "process.h"

using namespace std;

static map<UINT32, patch_struct*> patch_map;

// helpers
VOID regInit(REGSET* regsIn, REGSET* regsOut);

VOID INS_InstrumentINS(INS ins) {
	static int insCount = 0; // NOTE was in a global state, but we only use it here

	/* raise exception at second istruction after real trap	*/
	ExceptionHandler *eh = ExceptionHandler::getInstance();
	if (eh->isPendingException()) {
		//ProcInfo *pc = ProcInfo::getInstance();
		if (insCount == 0)
			insCount++;
		else {
			insCount = 0;
			INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)ExceptionHandler::executeExceptionIns, IARG_CONTEXT,
				IARG_THREAD_ID, IARG_ADDRINT, INS_Address(ins), IARG_END);
			return;
		}
	}

	// TODO register some callback for when the debugger reattaches
	if (_debugger && (PIN_GetDebugStatus() != DEBUG_STATUS_UNCONNECTABLE)) {
		//ProcInfo *gs = ProcInfo::getInstance();
		FetchGlobalState;
		if (gs->flagStep < 2) {//TODO && pc->isInsideMainIMG(INS_Address(ins)))
			gs->flagStep = gs->flagStep + 1;
			if (gs->flagStep == 1) {}
			else {
				// FIX PEB for debugging flags
				Process::patchPEB();
			}
		}
	}
	
	string cat = INS_Disassemble(ins);

	REGSET regsIn;
	REGSET regsOut;

	if (cat.find("cpuid") != string::npos) {

		regInit(&regsIn, &regsOut);
		ADDRINT curEip = INS_Address(ins);

		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)INS_patchCpuid_entry,
			IARG_INST_PTR,
			IARG_PARTIAL_CONTEXT, &regsIn, &regsOut,
			IARG_ADDRINT, curEip,
			IARG_END);
		INS_InsertCall(ins, IPOINT_AFTER, (AFUNPTR)INS_patchCpuid_exit,
			IARG_INST_PTR,
			IARG_PARTIAL_CONTEXT, &regsIn, &regsOut,
			IARG_ADDRINT, curEip,
			IARG_END);

	}
	else if (cat.find("rdtsc") != string::npos) {

		regInit(&regsIn, &regsOut);
		ADDRINT curEip = INS_Address(ins);

		INS_InsertCall(ins, IPOINT_AFTER, (AFUNPTR)INS_patchRtdsc_exit,
			IARG_INST_PTR,
			IARG_PARTIAL_CONTEXT, &regsIn, &regsOut,
			IARG_ADDRINT, curEip,
			IARG_END);

	}
	else if (cat.find("int 0x2d") != string::npos) {

		ADDRINT curEip = INS_Address(ins);

		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)INS_patchInt2d_entry,
			IARG_END);

	}
	else if (cat.find("in eax, dx") != string::npos) {

		regInit(&regsIn, &regsOut);
		ADDRINT curEip = INS_Address(ins);

		INS_InsertCall(ins, IPOINT_AFTER, (AFUNPTR)INS_patchIn_exit,
			IARG_PARTIAL_CONTEXT, &regsIn, &regsOut,
			IARG_END);

	}
	else if (cat.find("sti") != string::npos) {
		if (_debugger) {
			INS_Delete(ins);
		}
	}

}

VOID INS_patchRtdsc_exit(ADDRINT ip, CONTEXT * ctxt, ADDRINT cur_eip) {
	
	ACTIVE_HOOK(EN_rdtsc);

	// TODO add check on memory range for instruction?

	FetchTimeState;

	tinfo->_edx = (tinfo->_edx_eax & 0xffffffff00000000ULL) >> 32; // most significant 32
	tinfo->_edx_eax += tinfo->sleepMs; //add to result ms of previous sleep call
	tinfo->_eax = tinfo->_edx_eax & 0x00000000ffffffffULL; // less significant 32
	tinfo->_edx_eax += 30;
	tinfo->sleepMs = 0;

	PIN_SetContextReg(ctxt, REG_GAX, tinfo->_eax);
	PIN_SetContextReg(ctxt, REG_GDX, tinfo->_edx);

}

VOID INS_patchCpuid_entry(ADDRINT ip, CONTEXT * ctxt, ADDRINT cur_eip) {
	
	ACTIVE_HOOK(EN_cpuid);

	FetchHookTLS;

	ADDRINT _eax;
	PIN_GetContextRegval(ctxt, REG_GAX, reinterpret_cast<UINT8*>(&_eax));
	in->cpuid_eax = _eax;

}

VOID INS_patchCpuid_exit(ADDRINT ip, CONTEXT * ctxt, ADDRINT cur_eip) {
	
	ACTIVE_HOOK(EN_cpuid);

	FetchHookTLS;
	
	ADDRINT _ebx, _ecx, _edx;
	PIN_GetContextRegval(ctxt, REG_GDX, reinterpret_cast<UINT8*>(&_edx));
	PIN_GetContextRegval(ctxt, REG_GBX, reinterpret_cast<UINT8*>(&_ebx));
	PIN_GetContextRegval(ctxt, REG_GCX, reinterpret_cast<UINT8*>(&_ecx));

	if (in->cpuid_eax == 1) {
		// TODO add check on memory range for instruction?
		UINT32 mask = 0xFFFFFFFFULL;
		_ecx &= (mask >> 1);
	}
	else if (in->cpuid_eax >= 0x40000000 && in->cpuid_eax <= 0x400000FF) {
		LOG_AR("[CPUID] - 0x4");
		_ecx = 0x0ULL;
		_ebx = 0x0ULL;
		_edx = 0x0ULL;
	}

	PIN_SetContextReg(ctxt, REG_GCX, _ecx);
	PIN_SetContextReg(ctxt, REG_GBX, _ebx);
	PIN_SetContextReg(ctxt, REG_GDX, _edx);

}

VOID INS_patchInt2d_entry(CONTEXT * ctx, THREADID tid, ADDRINT accessAddr) {
	
	ACTIVE_HOOK(EN_int0x2d);

	LOG_AR("[INT 2D] - int 2d");

	// insert exception on int 2d
	ExceptionHandler *eh = ExceptionHandler::getInstance();
	eh->setExceptionToExecute(NTSTATUS_STATUS_BREAKPOINT);

}

VOID INS_patchIn_exit(CONTEXT * ctx) {
	
	ACTIVE_HOOK(EN_in);

	LOG_AR("[IN eax, dx] - vmware magic number");

	ADDRINT _ebx = 0;
	PIN_SetContextReg(ctx, REG_GBX, _ebx);

}

static VOID regInit(REGSET* regsIn, REGSET* regsOut) {
	REGSET_AddAll(*regsIn);
	REGSET_Clear(*regsOut);
	REGSET_Insert(*regsOut, REG_GAX);
	REGSET_Insert(*regsOut, REG_GBX);
	REGSET_Insert(*regsOut, REG_GDX);
	REGSET_Insert(*regsOut, REG_GCX);
}

/*** STEALTH CODE PATCHING ***/

BOOL INS_DisableInsStealth(string input, string *result) {

	string delimiter_addr = "_";
	string token;
	size_t pos = 0;
	size_t count_addr = 0;

	ADDRINT start_addr, end_addr;

	while ((pos = input.find(delimiter_addr)) != string::npos) {
		token = input.substr(0, pos);
		if (count_addr == 1) {
			UINT32 tmp = strtol(token.c_str(), NULL, 16);
			start_addr = tmp;
		}
		count_addr++;
		input.erase(0, pos + delimiter_addr.length());
	}
	UINT32 tmp = strtol(input.c_str(), NULL, 16);
	end_addr = tmp;

	for (UINT32 i = start_addr; i < end_addr; i++) {
		patch_map.erase(i);
	}

	PIN_RemoveInstrumentationInRange(start_addr, end_addr);

	*result = "OK";
	return TRUE;

}

BOOL INS_EnableInsStealth(string input, string *result) {

	patch_struct *ps = (patch_struct*)malloc(sizeof(patch_struct));

	string delimiter_addr = "_";
	string delimiter_patch = ",";
	size_t pos = 0;
	string token;
	size_t count_addr = 0;
	size_t count_patch = 0;

	/*	STRING HELPER: INIT_ADDR:END_ADDR:RET_ADDR:PATCH_CODE	*/
	/*	STRING EXAMPLE: set_40108F_401095_401098_83,e9,01	*/
	
	/*	ADDRESSES LOOP	*/
	while ((pos = input.find(delimiter_addr)) != string::npos) {
		token = input.substr(0, pos);
		if (count_addr == 1) {
			UINT32 tmp = strtol(token.c_str(), NULL, 16);
			ps->start = tmp;
		}
		else if (count_addr == 2) {
			UINT32 tmp = strtol(token.c_str(), NULL, 16);
			ps->fin = tmp;
		}
		else if (count_addr == 3) {
			UINT32 tmp = strtol(token.c_str(), NULL, 16);
			ps->ret = tmp;
		}
		count_addr++;
		input.erase(0, pos + delimiter_addr.length());
	}

	/*	PATCH LOOP	*/
	while ((pos = input.find(delimiter_patch)) != string::npos) {
		token = input.substr(0, pos);
		
		UINT32 tmp = strtol(token.c_str(), NULL, 16);
		ps->patch[count_patch] = (unsigned char)tmp;

		count_patch++;
		input.erase(0, pos + delimiter_patch.length());
	}
	/*	last byte	*/
	UINT32 tmp = strtol(input.c_str(), NULL, 16);
	ps->patch[count_patch] = (unsigned char)tmp;

	patch_map.insert(pair<UINT32, patch_struct*>(ADDR, ps));

	
	for (UINT32 j = ADDR + 1; j <= ADDR + 6; j++) {
		patch_map.insert(pair<UINT32, patch_struct*>(j, (patch_struct*)-1));
	}

	PIN_RemoveInstrumentationInRange(ps->start, ps->fin);

	*result = "OK";
	return TRUE;

}


VOID INS_HandlerInsStealth(CONTEXT *ctxt, ADDRINT addr) {

	patch_struct *ps = patch_map.find(addr)->second;
	size_t patch_len = strlen((char*)ps->patch);
	UINT32 addr_of_jmp = (UINT32)&ps->ret;
	UINT32 start = ps->start;
	
	unsigned char jmp_opc[] = { 0xff, 0x25 };

	VOID *mem = W::VirtualAlloc(NULL, PATCH_SIZE + JMP_OPC_SIZE + ADDR_SIZE, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	// push patch code	
	memcpy((VOID*)((UINT32)mem), ps->patch, patch_len);

	// push jmp opc
	memcpy((VOID*)((UINT32)mem + patch_len), (void*)jmp_opc, JMP_OPC_SIZE);

	// push jmp addr
	memcpy((VOID*)((UINT32)mem + patch_len + JMP_OPC_SIZE), (void*)&addr_of_jmp, ADDR_SIZE);

	PIN_SetContextReg(ctxt, REG_EIP, (ADDRINT)mem);
	PIN_ExecuteAt(ctxt);

}

VOID INS_AddInsStealth(INS ins) {

	map<UINT32, patch_struct*>::iterator ip = patch_map.find(INS_Address(ins));
	if (ip != patch_map.end()) {
		if (ip->second != (VOID*)-1) {
			INS_InsertCall(
				ins, 
				IPOINT_BEFORE,
				(AFUNPTR)INS_HandlerInsStealth,
				IARG_CONTEXT, IARG_ADDRINT,
				INS_Address(ins),
				IARG_END
			);
		}
		INS_Delete(ins);
	}

}