#pragma once
#include "pin.H"

namespace Process {

	BOOL VMMap(std::string* result);
	VOID patchPEB(int numCores);

	// instrumentation
	void OnImageLoad(IMG img);
	void OnImageUnload(IMG img);
};