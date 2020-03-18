#include "process.h"
#include "memory.h"
#include "state.h"
#include "itree.h"

#include <list> 
#include <iterator> 
#include <iostream>

#define SEG_PROT_R 4
#define SEG_PROT_W 2
#define SEG_PROT_X 1

using namespace std;

namespace Process {
	// helpers
	std::ostream& stringify(std::ostream& out, std::string const& s);

	VOID patchPEB(int numCores) {

		PEB32 *peb; // TODO we are retrieving it in one too many ways in the code :-)
		__asm {
			mov eax, fs:30h
			mov peb, eax
		}

		W::WriteProcessMemory((W::HANDLE)(-1), (W::LPVOID)(&peb->NumberOfProcessors), &numCores, sizeof(W::DWORD), 0);

	}

	/* From IDAngr - Thanks to Andrea Fioraldi */
	// TODO refine it when we have SoK info available? 
	BOOL Process::VMMap(string* result) {
		W::LPBYTE base = NULL;
		W::MEMORY_BASIC_INFORMATION mbi;
		ostringstream ss;

		BOOL has_map = FALSE;

		while (W::VirtualQuery(base, &mbi, sizeof(W::MEMORY_BASIC_INFORMATION)) > 0)
		{
			has_map = TRUE;
			ss << "[" << (size_t)mbi.BaseAddress << "," << (size_t)mbi.BaseAddress + mbi.RegionSize << ",";

			int mapperm = 0;
			if (mbi.Protect & PAGE_EXECUTE)
				mapperm = SEG_PROT_X;
			else if (mbi.Protect & PAGE_EXECUTE_READ)
				mapperm = SEG_PROT_X | SEG_PROT_R;
			else if (mbi.Protect & PAGE_EXECUTE_READWRITE)
				mapperm = SEG_PROT_X | SEG_PROT_R | SEG_PROT_W;
			else if (mbi.Protect &  PAGE_EXECUTE_WRITECOPY)
				mapperm = SEG_PROT_X | SEG_PROT_R;
			//else if (mbi.Protect & PAGE_NOACCESS)
			//	mapperm = 0;
			else if (mbi.Protect & PAGE_READONLY)
				mapperm = SEG_PROT_R;
			else if (mbi.Protect & PAGE_READWRITE)
				mapperm = SEG_PROT_R | SEG_PROT_W;
			else if (mbi.Protect & PAGE_WRITECOPY)
				mapperm = SEG_PROT_R;

			ss << mapperm << ",";

			IMG img = IMG_FindByAddress((ADDRINT)mbi.BaseAddress);
			if (IMG_Valid(img))
			{
				ss << "\"";
				if (IMG_IsMainExecutable(img)) {
					for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec)) {
						if (SEC_Address(sec) == (UINT32)mbi.BaseAddress) {
							stringify(ss, SEC_Name(sec));
							break;
						}
					}
				}
				else {
					stringify(ss, IMG_Name(img));
				}
				ss << "\"";
			}
			else
				ss << "\"<no name>\"";
			ss << "]" << endl;

			base += mbi.RegionSize;
		}

		*result = ss.str();
		result->pop_back();

		return has_map;
	}

	// credits: https://stackoverflow.com/questions/42711201/
	static std::ostream& stringify(std::ostream& out, std::string const& s) {
		for each (char ch in s)
		{
			switch (ch)
			{
			case '\'':
				out << "\\'";
				break;
			case '\"':
				out << "\\\"";
				break;
			case '\?':
				out << "\\?";
				break;
			case '\\':
				out << "\\\\";
				break;
			case '\a':
				out << "\\a";
				break;
			case '\b':
				out << "\\b";
				break;
			case '\f':
				out << "\\f";
				break;
			case '\n':
				out << "\\n";
				break;
			case '\r':
				out << "\\r";
				break;
			case '\t':
				out << "\\t";
				break;
			case '\v':
				out << "\\v";
				break;
			default:
				out << ch;
			}
		}
		return out;
	}

	void OnImageLoad(IMG img) {
		if (IMG_IsMainExecutable(img)) return; // we only want to track Windows DLLs

		const char* imgName = IMG_Name(img).c_str();
		char* data = strdup(imgName);
		size_t len = strlen(data) + 1;
		while (len--) data[len] = tolower(data[len]);

		if (strstr(data, "windows\\system32\\") || strstr(data, "windows\\syswow64\\") ||
				strstr(data, "windows\\winsxs\\")) {
			ADDRINT imgStart = IMG_LowAddress(img);
			ADDRINT imgEnd = IMG_HighAddress(img);
			
			PIN_LockClient(); // rendundant? check AOT hooks
			State::globalState* gs = State::getGlobalState();
			if (gs->dllRangeITree == NULL) {
				gs->dllRangeITree = itree_init(imgStart, imgEnd, (void*)data);
			} else {
				bool success = itree_insert(gs->dllRangeITree, imgStart, imgEnd, (void*)data);
				if (!success) {
					LOG_AR("Duplicate range insertion for DLL %s", data);
					fprintf(stderr, "==> Duplicate range insertion for DLL %s\n", data);
				}
			}
			PIN_UnlockClient();
			// debugging
			//fprintf(stderr, "==> Added DLL %s with range %0x->%0x\n", data, imgStart, imgEnd);
			bool validIntervalTree = itree_verify(gs->dllRangeITree);
			if (!validIntervalTree) {
				itree_print(gs->dllRangeITree, 0);
				ASSERT(false, "Broken DLL interval tree");
			}

		}
		else {
			free(data);
			return;
		}


	}

	void OnImageUnload(IMG img) {
		if (IMG_IsMainExecutable(img)) return; // only for clarity

		ADDRINT imgStart = IMG_LowAddress(img);
		ADDRINT imgEnd = IMG_HighAddress(img);
		PIN_LockClient();
		State::globalState* gs = State::getGlobalState();
		if (gs->dllRangeITree) {
			// oblivious delete
			gs->dllRangeITree = itree_delete(gs->dllRangeITree, imgStart, imgEnd);
			// debugging
			//fprintf(stderr, "==> Deleted DLL %s with range %0x->%0x\n", IMG_Name(img).c_str(), imgStart, imgEnd);
			bool validIntervalTree = itree_verify(gs->dllRangeITree);
			if (!validIntervalTree) {
				itree_print(gs->dllRangeITree, 0);
				ASSERT(false, "Broken DLL interval tree");
			}
		}
		PIN_UnlockClient();
	}

	VOID CheckRetAddrLibcall(ADDRINT* ESP) {
		State::globalState* gs = State::getGlobalState();
		State::hookEntryArgsTLS* hookTls = State::getHookEntryTLSArgs();
		itreenode_t* node = itree_search(gs->dllRangeITree, *ESP);
		hookTls->retAddrInDLL = (node) ? true : false;
		hookTls->retAddrInDll_data = (node) ? (const char*)node->data : (const char*)NULL;
		hookTls->retAddr = *ESP;
	}

}
