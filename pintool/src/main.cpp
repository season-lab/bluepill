#include "pin.H"
#include <iostream>

#include "config.h"
#include "memory.h"
#include "syshooking.h"
#include "fpu.h"
#include "context.h"
#include "logging.h"
#include "ins.h"
#include "exceptionHandler.h"
#include "functions.h"
#include "state.h"
#include "process.h"
#include "wmi.h"

// libdft
#include "libdft/libdft_config.h"
#include "libdft/bridge.h"
#include "libdft/libdft_api.h"
#include "libdft/tagmap.h"

using namespace std;


TLS_KEY tls_key = INVALID_TLS_KEY;

#if !FIXED_KNOBS
BOOL _nxKnob;
BOOL _paranoidKnob;
BOOL _rwKnob;
BOOL _leakKnob;
BOOL _libdftKnob;
BOOL _evasions;
BOOL _debugger;
#endif

// knobs for BluePill
KNOB <BOOL> KnobEvasions(KNOB_MODE_WRITEONCE, "pintool",
	"evasions", "false", "enable observe-check-replace hooks");
KNOB <BOOL> KnobDebugger(KNOB_MODE_WRITEONCE, "pintool",
	"debugger", "false", "enable debugging");

// knobs from SoK DBI anti-evasion
KNOB <BOOL> KnobNX(KNOB_MODE_WRITEONCE, "pintool",
	"nx", "false", "enable nx protection");
KNOB <BOOL> KnobParanoid(KNOB_MODE_WRITEONCE, "pintool",
	"paranoid", "false", "enable nx full protection");
KNOB <BOOL> KnobRW(KNOB_MODE_WRITEONCE, "pintool",
	"read_write", "false", "enable read/write protection");
KNOB <BOOL> KnobLeak(KNOB_MODE_WRITEONCE, "pintool",
	"leak", "false", "enable fpu context protection");

// knobs for libdft
KNOB <BOOL> KnobLibdft(KNOB_MODE_WRITEONCE, "pintool",
	"libdft", "false", "setup libdft");

// very useful help message
INT32 Usage() {
	cout << "Hi there :-) Have fun with BluePill!\n" << endl;

	cout << KNOB_BASE::StringKnobSummary() << endl;

	return -1;
}

// custom commands that we define over GDB remote server protocol
// -> attach-detach feature to get around problems in exception handling
// -> transfer memory map information missing in GDB
// -> add/remove (stealth) code patches
static BOOL DebugInterpreter(THREADID tid, CONTEXT *ctxt, const string &cmd, string *result, VOID *) {
	std::cout << "GDB Command: " << cmd << std::endl;

	if (cmd.compare("wait") == 0) {
		//ProcInfo* gs = ProcInfo::getInstance();
		FetchGlobalState;
		gs->waitForDebugger = TRUE;
		*result = "Pin will wait debugger after exception...";
		return TRUE;
	}
	else if (cmd.compare("vmmap") == 0) {
		return Process::VMMap(result);
	}
	else if (cmd.find("set") != string::npos) {
		return INS_EnableInsStealth(cmd, result);
	}
	else if (cmd.find("rm") != string::npos) {
		return INS_DisableInsStealth(cmd, result);
	}
	// [...]
	*result = "Command not found!";
	return TRUE;  // Unknown command

}

VOID PINTOOL_Config() {

	Logging::LOGGING_Init();

	// obtain a TLS key
	tls_key = PIN_CreateThreadDataKey(NULL);
	if (tls_key == INVALID_TLS_KEY) {
		LOG_AR("Cannot initialize TLS");
		PIN_ExitProcess(1);
	}

#if !FIXED_KNOBS
	_leakKnob = KnobLeak.Value();
	_rwKnob = KnobRW.Value();
	_nxKnob = KnobNX.Value();
	_paranoidKnob = KnobParanoid.Value();
	_libdftKnob = KnobLibdft.Value();
	_evasions = KnobEvasions.Value();
	_debugger = KnobDebugger.Value();
#endif

}

VOID FiniCallback(INT32 code, VOID *v) {
	//Logging::LOGGING_Shutdown();
}

VOID OnThreadStart(THREADID tid, CONTEXT *ctxt, INT32, VOID *) {
	// TLS handling
	SYSHOOKING::SetTLSKey(tid);

	// [SoK DBI evasions] Map memory associated with new thread
	MEMORY_OnThreadStart(ctxt);

	//libdft
	if (_libdftKnob) {
		thread_ctx_t *thread_ctx = libdft_thread_start(ctxt);
		#define TTINFO(field) thread_ctx->ttinfo.field
		TTINFO(tid) = tid;
		TTINFO(os_tid) = PIN_GetTid();
		char tmp[32];
		sprintf(tmp, "tainted-%u.log", TTINFO(os_tid));
		TTINFO(logname) = strdup(tmp);
		#undef TTINFO
	}
}

VOID OnThreadFini(THREADID tid, const CONTEXT *ctxt, INT32, VOID *) {
	if (_libdftKnob)
		libdft_thread_fini(ctxt);
}

// Instruction instrumentation
VOID Instruction(INS ins, VOID *v) {
	if (_debugger) // stealth code patching
		INS_AddInsStealth(ins);

	if (_rwKnob || _nxKnob) // [SoK DBI evasions]
		MEMORY_InstrumentINS(ins);
	if (_leakKnob) // [SoK DBI evasions]
		FPU_InstrumentINS(ins);
	
	if (_evasions) // BluePill low-level hooks
		INS_InstrumentINS(ins);
	
	//if (_libdftKnob) instrumentForTaintCheck(ins, NULL);
}

// AOT instrumentation
VOID Image(IMG img, VOID* v) {
	if (_rwKnob || _nxKnob) { // [SoK DBI evasions]
		MEMORY_LoadImage(img);
	}
	Process::OnImageLoad(img);
	Functions::AddHooks(img); // BluePill API hooks
}

VOID ImageUnload(IMG img, VOID* v) {
	if (_rwKnob || _nxKnob) { // [SoK DBI evasions]
		MEMORY_UnloadImage(img);
	}
	Process::OnImageUnload(img);
}


/********************
STUFF FOR DEBUGGING
********************/
VOID KKTM2() { // debug specific function
	cout << "[CIAO]" << endl;
}

VOID KKTM(const char* str) { // trivial logger for API calls
	cout << str << endl;
}

// for debugging purposes (default: unregistered)
static VOID InstrumentRoutine(RTN rtn, VOID *) {
#if 1
	const char* rtnName = RTN_Name(rtn).c_str();

	RTN_Open(rtn);
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)KKTM, IARG_ADDRINT, rtnName, IARG_END);
	RTN_Close(rtn);

#endif
#if 0
	if (RTN_Name(rtn).find("ExecQuery") != string::npos) {
		RTN_Open(rtn);
		RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)KKTM2, IARG_END);
		RTN_Close(rtn);
	}
#endif
}
/**** END OF STUFF FOR DEBUGGING ***/

int main(int argc, char *argv[]) {

	PIN_InitSymbols();
	if (PIN_Init(argc, argv)) {
		return Usage();
	}

	// check Wow64 information
	W::BOOL bWow64;
	W::IsWow64Process((W::HANDLE)(-1), &bWow64);
	Process::isWow64 = (bWow64 != 0);

	// initialize some stuff
	PINTOOL_Config();
	Functions::Init();

	// set up elements to be hidden
	HiddenElements::initializeHiddenStuff();

	if (_rwKnob || _nxKnob) {
		MEMORY_Init();
	}

	if (_leakKnob) {
		FPU_Init();
	}

	// syscall instrumentation: PIN_AddSyscallEntryFunction, PIN_AddSyscallExitFunction
	SYSHOOKING::Init();

	// INS instrumentation
	INS_AddInstrumentFunction(Instruction, NULL);

	// AOT instrumentation (IMG)
	IMG_AddInstrumentFunction(Image, NULL);
	IMG_AddUnloadFunction(ImageUnload, NULL);
	
	// process PEB
	Process::patchPEB();

	// exceptional control flow (see context.cpp)
	PIN_AddContextChangeFunction(CONTEXT_ChangeContext, NULL);
	PIN_AddInternalExceptionHandler(CONTEXT_InternalExceptionHandler, NULL);

	// events
	PIN_AddThreadStartFunction(OnThreadStart, NULL);
	PIN_AddThreadFiniFunction(OnThreadFini, NULL);

	// libdft initialization
	if (_libdftKnob) {
		if (libdft_init_data_only()) {
			LOG_AR("Error initializing libdft");
			exit(1);
		}
		TRACE_AddInstrumentFunction(libdft_trace_inspect, NULL);
		//INS_AddInstrumentFunction(instrumentForTaintCheck, NULL);
	}
	
	// debugger
	if (_debugger) {
		PIN_AddDebugInterpreter(DebugInterpreter, nullptr);
		// TODO merge GUI thread here when we release that component
	}

	// routine instrumentation (for debugging only)
	//RTN_AddInstrumentFunction(InstrumentRoutine, NULL);
	
	// process exit callback
	PIN_AddFiniFunction(FiniCallback, NULL);

	PIN_StartProgram();
	return 0;
}
