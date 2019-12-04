#include "exceptionHandler.h"

ExceptionHandler::ExceptionHandler() {
	this->pending = FALSE;
}

ExceptionHandler* ExceptionHandler::instance = nullptr; //singleton

ExceptionHandler* ExceptionHandler::getInstance() {
	if (instance == nullptr)
		instance = new ExceptionHandler();
	return instance;
}

void ExceptionHandler::setExceptionToExecute(W::UINT32 exceptionCode) {
	this->pending = TRUE;
	this->code = exceptionCode;
}

bool ExceptionHandler::isPendingException() {
	return this->pending;
}

void ExceptionHandler::raisePendingException(CONTEXT *ctx, THREADID tid, ADDRINT accessAddr) {
	EXCEPTION_INFO exc;
	// we are interested only in a Windows environment
	PIN_InitWindowsExceptionInfo(&exc, this->code, accessAddr);
	PIN_SetContextReg(ctx, REG_INST_PTR, PIN_GetContextReg(ctx, REG_INST_PTR) + 0x1); // add 0x1 to get the right address
	this->pending = FALSE;
	PIN_RaiseException(ctx, tid, &exc);
}

void ExceptionHandler::executeExceptionIns(CONTEXT *ctx, THREADID tid, ADDRINT accessAddr) {
	ExceptionHandler *eh = ExceptionHandler::getInstance();
	eh->raisePendingException(ctx, tid, accessAddr);
}

void ExceptionHandler::setCode(W::UINT32 exceptionCode) {
	this->code = exceptionCode;
}