#pragma once
#include "pin.H"
#include "libdft_api.h"

extern REG thread_ctx_ptr;

void instrumentForTaintCheck(INS ins, void*);
void registerThreadTaintAnalysis(THREADID tid, thread_ctx_t* thread_ctx);