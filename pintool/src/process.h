#pragma once
#include "pin.H"

namespace Process {
	extern BOOL isWow64;

	// patch PEB fields
	VOID patchPEB();

	// for GDB remote debugging
	BOOL VMMap(std::string* result);
	
	// instrumentation
	void OnImageLoad(IMG img);
	void OnImageUnload(IMG img);

	// check on return address
	VOID CheckRetAddrLibcall(ADDRINT* ESP);

};