#include "fpu.h"

#include <iostream>

using namespace std;

REG spilledFpu;

VOID FPU_Init() {

	spilledFpu = PIN_ClaimToolRegister();

}

VOID PIN_FAST_ANALYSIS_CALL FPU_UpdateFPUStatus(ADDRINT regValue, ADDRINT op) {

	LOG_AR("Possible FPU Leak");
	PIN_SafeCopy((VOID *)(op + FPUIPOFFSET), &regValue, sizeof(ADDRINT));

}

ADDRINT PIN_FAST_ANALYSIS_CALL FPU_UpdateLastFpuIns(ADDRINT addr) { 

	return addr;

}

VOID FPU_InstrumentINS(INS ins) {

	if (INS_Category(ins) == XED_CATEGORY_X87_ALU) {

		string code = INS_Disassemble(ins);
		
		if (code.find("fwait") != string::npos) return;

		if (code.find("fnstenv") != string::npos || code.find("fstenv") != string::npos ||
			code.find("fsave") != string::npos || code.find("fnsave") != string::npos ||
			code.find("fxsave") != string::npos) {
			
			INS_InsertCall(ins, IPOINT_AFTER,
				(AFUNPTR)FPU_UpdateFPUStatus,
				IARG_FAST_ANALYSIS_CALL,
				IARG_REG_VALUE, spilledFpu,
				IARG_MEMORYOP_EA, 0,
				IARG_END);
				
		}
		else { //TODO specify only ins that change FPU state

			INS_InsertCall(ins, IPOINT_AFTER,
				(AFUNPTR)FPU_UpdateLastFpuIns,
				IARG_FAST_ANALYSIS_CALL,
				IARG_INST_PTR,
				IARG_RETURN_REGS, spilledFpu,
				IARG_END);
				
		}

		/*
		UINT32 opc = 0; //need this
		ADDRINT addr = INS_Address(ins);
		USIZE size = INS_Size(ins);
		PIN_SafeCopy(&opc, (void*)addr, size);
		cout << INS_Disassemble(ins) << " 0x" << hex << opc << " " << size << endl;
		opc &= 0xFF;
		cout << INS_Disassemble(ins) << " N0x" << hex << opc << endl;
		if (opc == 0x9B) return;
		if (opc == 0xD9 || 0xDD) cout << INS_Disassemble(ins) << endl;;
		*/
	}

}