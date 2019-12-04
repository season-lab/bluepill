#pragma once
#include "pin.H"
#include <iostream>

namespace W {
	#include "windows.h"
}

class ExceptionHandler { // TODO turn it into a namespace

public:
	static ExceptionHandler* getInstance();
	static void executeExceptionIns(CONTEXT *ctx, THREADID tid, ADDRINT accessAddr);
	void setExceptionToExecute(W::UINT32 exceptionCode);
	void raisePendingException(CONTEXT *ctx, THREADID tid, ADDRINT accessAddr);
	bool isPendingException();
	void setCode(W::UINT32 exceptionCode);

	ADDRINT lastAddress;
	W::UINT32 code;
	bool pending;
	THREADID tid;
	CONTEXT *ctx;

private:
	ExceptionHandler();

	static ExceptionHandler* instance;
};
