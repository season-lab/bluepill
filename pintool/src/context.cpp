#include "context.h"
#include "config.h"
#include "exceptionHandler.h"
#include "state.h"
#include "winheaders.h"

#include <iostream>

VOID CONTEXT_ChangeContext(THREADID threadIndex, CONTEXT_CHANGE_REASON reason, const CONTEXT * ctxtFrom, CONTEXT * ctxtTo, INT32 info, VOID* v) {
	if (reason == CONTEXT_CHANGE_REASON_EXCEPTION) { // ==4
		FetchGlobalState;
		if (_debugger && gs->waitForDebugger) {
			PIN_WaitForDebuggerToConnect(99000);
			gs->waitForDebugger = FALSE;
			gs->flagStep = 0;
		}

#if 0
		ADDRINT _eip;
		PIN_GetContextRegval(ctxtFrom, REG_INST_PTR, reinterpret_cast<UINT8*>(&_eip));

		LOG_AR("CAPOZI %08x %08x", _eip, info); // debug messages we like :-)
#endif
	}
}


EXCEPT_HANDLING_RESULT CONTEXT_InternalExceptionHandler(THREADID tid, EXCEPTION_INFO *pExceptInfo, PHYSICAL_CONTEXT *pPhysCtxt, VOID *v) {
	std::cout << PIN_ExceptionToString(pExceptInfo).c_str() << " Code: " << pExceptInfo->GetExceptCode() << std::endl; // TODO use macro to print
																								 // handles single-step exception 
	if (pExceptInfo->GetExceptCode() == EXCEPTCODE_DBG_SINGLE_STEP_TRAP) {
		LOG_AR("[SINGLE_STEP] - *");
		ExceptionHandler *eh = ExceptionHandler::getInstance();
		eh->setExceptionToExecute(NTSTATUS_STATUS_BREAKPOINT);
		return EHR_HANDLED;
	}

	//LOG_INFO("******Caught Exception:******\n");
	//LOG_INFO("%s", PIN_ExceptionToString(pExceptInfo).c_str());
	//LOG_INFO("*****Continue to search a valid exception handler******\n");
	return EHR_CONTINUE_SEARCH;
}
