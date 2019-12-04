#pragma once
#include "pin.H"

namespace Process {

	BOOL VMMap(std::string* result);
	VOID patchPEB(int numCores);

};