#pragma once
#include "pin.H"
#include "logging.h"

VOID CONTEXT_ChangeContext(THREADID threadIndex, CONTEXT_CHANGE_REASON reason,
	const CONTEXT *ctxtFrom, CONTEXT *ctxtTo, INT32 info, VOID* v);

EXCEPT_HANDLING_RESULT CONTEXT_InternalExceptionHandler(THREADID tid,
	EXCEPTION_INFO *pExceptInfo, PHYSICAL_CONTEXT *pPhysCtxt, VOID *v);