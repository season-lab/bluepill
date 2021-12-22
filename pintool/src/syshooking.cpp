#include "pin.H"

#include "syshooking.h"
#include "memory.h"
#include "syshooks.h"

#include <iostream>

#include "process.h"
#include "state.h"
#include "HiddenElements.h"
#include "helper.h"
#include "itree.h"


namespace W {
#include "windows.h"
}

extern TLS_KEY tls_key;

namespace SYSHOOKING {
	CHAR* syscallIDs[MAXSYSCALLS];
	ADDRINT ntdllImgStart, ntdllImgEnd;

	typedef bool(*t_checkCS)(itreenode_t* node, itreenode_t* root, ADDRINT* ESP);
	t_checkCS checkCS_callback;

	// entries NULL by default (POD)
	syscall_hook sysEntryHooks[MAXSYSCALLS];
	syscall_hook sysExitHooks[MAXSYSCALLS];
	syscall_hook win32sysEntryHooks[MAXWIN32KSYSCALLS-0x1000];
	syscall_hook win32sysExitHooks[MAXWIN32KSYSCALLS-0x1000];

	// helpers
	VOID getNtdllRangesAndWow64Info();
	VOID enumSyscalls();
	VOID registerHooks();
	VOID getArgumentsOnEntry(CONTEXT *ctx, SYSCALL_STANDARD std, int count, ...);
	int lookupIndex(const char* syscallName);
	bool checkCallSiteNTDLLWin32(itreenode_t* node, itreenode_t* root, ADDRINT* ESP);
	bool checkCallSiteNTDLLWow64(itreenode_t* node, itreenode_t* root, ADDRINT* ESP);

	VOID Init() {
		getNtdllRangesAndWow64Info();
		enumSyscalls();
		registerHooks();
	}

	// for now this TLS is used for syscall info only
	// TODO merge it with stuff from state.h etc?
	VOID SetTLSKey(THREADID tid) {
		pintool_tls* tdata = new pintool_tls; // POD is zero-initialized

		if (PIN_SetThreadData(tls_key, tdata, tid) == FALSE) {
			LOG_AR("PIN_SetThreadData failed");
			PIN_ExitProcess(1);
		}
	}

	// analysis callback for Pin
	VOID SyscallEntry(THREADID thread_id, CONTEXT *ctx, SYSCALL_STANDARD std, void *v) {
		ADDRINT syscall_number = PIN_GetSyscallNumber(ctx, std);

		if (syscall_number == 0) {
			LOG_AR("==> WARNING: 0 system call number, possible int 2e case?");
			return;
		}

		pintool_tls *tdata = static_cast<pintool_tls*>(PIN_GetThreadData(tls_key, thread_id));
		syscall_t *sc = &tdata->sc;

		sc->syscall_number = syscall_number;

		// TODO for testing purposes
		//if (ReturnsToUserCode(ctx)) {
		//	fprintf(stderr, "Syscall %d returns to user code!\n", syscall_number);
		//}

		//if (!(_rwKnob || _nxKnob)) return; // TODO

		if (syscall_number < MAXSYSCALLS) {
			syscall_hook hookEntry = sysEntryHooks[syscall_number];
			syscall_hook hookExit = sysExitHooks[syscall_number];

			if (hookEntry || hookExit) { // fill sc (we may have a hook on exit only)
				// TODO selective filling :-/ we need to add prototypes
				getArgumentsOnEntry(ctx, std, SYSCALL_NUM_ARG,
					0, &sc->arg0, 1, &sc->arg1, 2, &sc->arg2, 3, &sc->arg3,
					4, &sc->arg4, 5, &sc->arg5, 6, &sc->arg6, 7, &sc->arg7,
					8, &sc->arg8, 9, &sc->arg9, 10, &sc->arg10, 11, &sc->arg11);

				// call onEntry hook
				if (hookEntry) hookEntry(sc, ctx, std);
			}
		} else if (sc->syscall_number >= 0x1000 && sc->syscall_number < MAXWIN32KSYSCALLS) {
			ADDRINT num = sc->syscall_number - 0x1000;
			syscall_hook hookEntry = win32sysEntryHooks[num];
			syscall_hook hookExit = win32sysExitHooks[num];

			if (hookEntry || hookExit) { // fill sc (we may have a hook on exit only)
				// TODO selective filling :-/ we need to add prototypes
				getArgumentsOnEntry(ctx, std, SYSCALL_NUM_ARG,
					0, &sc->arg0, 1, &sc->arg1, 2, &sc->arg2, 3, &sc->arg3,
					4, &sc->arg4, 5, &sc->arg5, 6, &sc->arg6, 7, &sc->arg7,
					8, &sc->arg8, 9, &sc->arg9, 10, &sc->arg10, 11, &sc->arg11);

				// call onEntry hook
				if (hookEntry) hookEntry(sc, ctx, std);
			}
		}
	}

	// analysis callback for Pin
	VOID SyscallExit(THREADID thread_id, CONTEXT *ctx, SYSCALL_STANDARD std, void *v) {
		pintool_tls *tdata = static_cast<pintool_tls*>(PIN_GetThreadData(tls_key, thread_id));
		syscall_t *sc = &tdata->sc;

		//if (!(_rwKnob || _nxKnob)) return; // TODO

		// TODO at some point we will build an array for win32k syscalls
		// where we subtract 0x1000 from the ordinal. For now we leave
		// this garbage with multiple if statements :-)
		if (sc->syscall_number < MAXSYSCALLS) {
			syscall_hook hook = sysExitHooks[sc->syscall_number];
			if (hook) hook(sc, ctx, std);
		} else if (sc->syscall_number >= 0x1000 && sc->syscall_number < MAXWIN32KSYSCALLS) {
			ADDRINT num = sc->syscall_number - 0x1000;
			syscall_hook hook = win32sysExitHooks[num];
			if (hook) hook(sc, ctx, std);
		}
	}

	BOOL ReturnsToUserCode(CONTEXT* ctx) {
		ADDRINT *ESP = (ADDRINT*)PIN_GetContextReg(ctx, REG_STACK_PTR);
		State::globalState* gs = State::getGlobalState();
		itreenode_t* node = itree_search(gs->dllRangeITree, *ESP);
		if (node) { // we might be inside ntdll though
			return checkCS_callback(node, gs->dllRangeITree, ESP);
		}
		return TRUE;
	}

	/** HELPER METHODS BEGIN HERE **/
 
	// used in getNtdllRangesAndWow64Info()
	typedef NTSYSAPI W::PIMAGE_NT_HEADERS NTAPI _RtlImageNtHeader(
		W::PVOID ModuleAddress
	);

	static VOID getNtdllRangesAndWow64Info() {
		checkCS_callback = (Process::isWow64) ? checkCallSiteNTDLLWow64 : checkCallSiteNTDLLWin32;

		// credits https://www.oipapio.com/question-547093 as
		// I couldn't use GetModuleInformation from psapi.dll
		// (unless I wanted to load the library dynamically)
		W::HMODULE image = W::GetModuleHandle("ntdll");

		_RtlImageNtHeader* fun = (_RtlImageNtHeader*)W::GetProcAddress(image, "RtlImageNtHeader");
		W::PIMAGE_NT_HEADERS headers = fun(image);

		ntdllImgStart = (ADDRINT)headers->OptionalHeader.ImageBase; // == (ADDRINT)image
		ntdllImgEnd = ntdllImgStart + headers->OptionalHeader.SizeOfImage;
	}

	// ntdll parsing for syscall ordinal extraction
	// Win10 support by borrowing from SNIPER https://github.com/dcdelia/sniper
	static VOID enumSyscalls() {
		unsigned char *image = (unsigned char *)W::GetModuleHandle("ntdll");
		W::IMAGE_DOS_HEADER *dos_header = (W::IMAGE_DOS_HEADER *) image;
		W::IMAGE_NT_HEADERS *nt_headers = (W::IMAGE_NT_HEADERS *)(image + dos_header->e_lfanew);
		W::IMAGE_DATA_DIRECTORY *data_directory = &nt_headers->
			OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
		W::IMAGE_EXPORT_DIRECTORY *export_directory = (W::IMAGE_EXPORT_DIRECTORY *)(image + data_directory->VirtualAddress);
		W::DWORD *address_of_names = (W::DWORD*)(image + export_directory->AddressOfNames);
		W::DWORD *address_of_functions = (W::DWORD*)(image + export_directory->AddressOfFunctions);
		UINT16 *address_of_name_ordinals = (W::UINT16*)(image + export_directory->AddressOfNameOrdinals);
		W::DWORD number_of_names = MIN(export_directory->NumberOfFunctions, export_directory->NumberOfNames);

		for (W::DWORD i = 0; i < number_of_names; i++) {
			const char *name = (const char *)(image + address_of_names[i]);
			unsigned char *addr = image + address_of_functions[address_of_name_ordinals[i]];
			if (!memcmp(name, "Zw", 2) || !memcmp(name, "Nt", 2)) {
#ifdef __LP64__
				// 64-bit Windows is standard among releases
				// mov r10, rcx ; mov eax, sycall_number ; syscall; ret
				// 4C 8B D1 ; B8 ?? ?? ?? ?? ; 0F 05 ; C3
				if (addr[0] == 0x4C && addr[3] == 0xB8) {
					UINT16 syscall_number = *(UINT16*)(addr + 4); // could read UINT32 as well
					if (!syscallIDs[syscall_number] || (!memcmp(name, "Nt", 2) && !memcmp(name, "Zw", 2))) {
						syscallIDs[syscall_number] = strdup(name);
					}
				}
#else
				// does the signature match one of these cases? https://gist.github.com/wbenny/b08ef73b35782a1f57069dff2327ee4d
				// 1:   > WoW64 on Windows XP and Windows 7
				//      mov eax, syscall_number ; mov ecx, imm32 ; lea edx, [esp+04h] ; call fs:[C0h]
				//		mov eax, syscall_number ; xor ecx, ecx ; lea edx, [esp+04h] ; call fs:[C0h]
				//		B8 ?? ?? ?? ?? ; [33 C9 | B9 ?? ?? ?? ??] ; 8D 54 24 04 ; 64 FF 15 C0 00 00 00
				//		epilogue is add esp, 4 ; retn [??] on Windows 7 while XP has no add
				//		83 C4 04 ; [C2 ?? ?? | C3]
				// 2:   > WoW64 on Windows 8 and 8.1 - TODO untested, need a 64-bit Win8 VM :-)
				//		mov eax, syscall_number; call large dword ptr fs:0C0h ; retn [??] 
				//		B8 ?? ?? ?? ?? ; 64 FF 15 C0 00 00 00 ; [C2 ?? ?? | C3]  
				// 3:   > WoW64 on Windows 10
				//		mov eax, syscall_number; mov edx, imm32; call edx ; retn [??]
				//		B8 ?? ?? ?? ?? ; B9 ?? ?? ?? ??] ; FF D2 ; [C2 ?? ?? | C3]  
				// 4:   > x86 - Windows XP and Windows 7
				//      mov eax, syscall_number ; mov edx, 0x7ffe0300 ; call dword near [edx] ; retn [??] for XP SP3 or 7
				//		mov eax, syscall_number ; mov edx, 0x7ffe0300 ; call edx ; retn [??] for XP before SP3
				//      B8 ?? ?? ?? ?? ; BA 00 03 FE 7F; [FF D2 | FF 12] ; [C2 ?? ?? | C3]
				// 5:	> x86 - Windows 8, 8.1, 10 - TODO untested, need a 32-bit Win8/Win10 VM :)
				//		mov eax, syscall_number ; call $+?? ; retn [??] ; mov edx, esp ; sysenter ; ret
				//		B8 ?? ?? ?? ?? ; E8 ?? 00 00 00 ; [C2 ?? ?? | C3] ; 8B D4 ; 0F 34 ; C3
				if (addr[0] == 0xb8 && (addr[5] == 0xB9		// case 1 and 3
									|| addr[5] == 0x33	// case 1
									//|| addr[5] == 0x64	// case 2 - untested!
									|| addr[5] == 0xBA	// case 4
									//|| addr[5] == 0xE8  // case 5 - untested!
					)) {
					// on Windows 10 the syscall ordinal will be in the two least significant bytes
					// while the remaining two may be non-zero; we ignore them by reading an UINT16
					UINT16 syscall_number = *(UINT16*)(addr + 1);
					if (!syscallIDs[syscall_number] || (!memcmp(name, "Nt", 2) && !memcmp(name, "Zw", 2))) {
						syscallIDs[syscall_number] = strdup(name);
					}
				}
#endif
			}
		}
	}

	static int lookupIndex(const char* syscallName) {
		for (int i = 0; i < MAXSYSCALLS; ++i) {
			if (!strcmp(syscallIDs[i], syscallName)) return i;
		}

		ASSERT(false, "Unknown system call number");
		return 0;
	}

	static VOID getArgumentsOnEntry(CONTEXT *ctx, SYSCALL_STANDARD std, int count, ...) {
		va_list args;
		va_start(args, count);
		for (int i = 0; i < count; i++) {
			int index = va_arg(args, int);
			ADDRINT *ptr = va_arg(args, ADDRINT *);
			*ptr = PIN_GetSyscallArgument(ctx, std, index);
		}
		va_end(args);
	}

	static bool checkCallSiteNTDLLWin32(itreenode_t* node, itreenode_t* root, ADDRINT* ESP) {
		ADDRINT addr = *ESP;
		if (addr < ntdllImgStart || addr > ntdllImgEnd) return false;

		// not much black magic: retn [say 10h] or ret
		// C2 10 00
		uint8_t bytes[3] = { 0xFF, 0xFF, 0xFF }; // TODO 0 might be fine as well
		PIN_SafeCopy(bytes, (void*)addr, 6);

		if (!((bytes[0] == 0xC2 && bytes[2] == 0x00) || bytes[0] == 0xC3)) {
			ASSERT(false, "Check implementation for NTDLL call sites");
			return false;
		}

		// the RA for the caller will be at ESP+4
		ADDRINT ra = *((ADDRINT*)ESP + 1);

		node = itree_search(root, ra);
		if (node) {
			//mycerr << "Syscall originated in " << node->dll_name
			//		 << " and would resume at " << ra << std::endl;
			return false;
		}

		return true;
	}

	static bool checkCallSiteNTDLLWow64(itreenode_t* node, itreenode_t* root, ADDRINT* ESP) {
		ADDRINT addr = *ESP;
		if (addr < ntdllImgStart || addr > ntdllImgEnd) return false;

		// black magic: add esp, 4 followed by retn [say 10h] or ret
		// 83 C4 04
		// C2 10 00
		uint8_t bytes[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }; // TODO 0 might be fine as well
		PIN_SafeCopy(bytes, (void*)addr, 6);
		if (!(bytes[0] == 0x83 && bytes[1] == 0xC4 && bytes[2] == 0x04)) {
			ASSERT(false, "Check implementation for NTDLL call sites");
			return false;
		}

		if (!((bytes[3] == 0xC2 && bytes[5] == 0x00) || bytes[3] == 0xC3)) {
			ASSERT(false, "Check implementation for NTDLL call sites");
			return false;
		}

		// the RA for the caller will be at ESP+4
		ADDRINT ra = *((ADDRINT*)ESP + 1);

		node = itree_search(root, ra);
		if (node) {
			//mycerr << "Syscall originated in " << node->dll_name
			//		  << " and would resume at " << ra << std::endl;
			return false;
		}

		return true;
	}


	static VOID registerHooks() {
		if (_rwKnob || _nxKnob) { // SoK DBI anti-evasion
			sysExitHooks[lookupIndex("NtProtectVirtualMemory")] = &SYSHOOKS::NtProtectVirtualMemory_exit; //&SYSHOOKS::GenericScan_exit;
			sysExitHooks[lookupIndex("NtUnmapViewOfSection")] = &SYSHOOKS::GenericScan_exit; // &SYSHOOKS::NtUnmapViewOfSection_exit;
			sysExitHooks[lookupIndex("NtFreeVirtualMemory")] = &SYSHOOKS::NtFreeVirtualMemory_exit;
			sysExitHooks[lookupIndex("NtFreeUserPhysicalPages")] = &SYSHOOKS::NtFreeUserPhysicalPages_exit;
			sysExitHooks[lookupIndex("NtQueryVirtualMemory")] = &SYSHOOKS::NtQueryVirtualMemory_exit;
			sysExitHooks[lookupIndex("NtAllocateVirtualMemory")] = &SYSHOOKS::NtAllocateVirtualMemory_exit;
			sysExitHooks[lookupIndex("NtAllocateUserPhysicalPages")] = &SYSHOOKS::GenericScan_exit; // &SYSHOOKS::NtAllocateUserPhysicalPages_exit;
			sysExitHooks[lookupIndex("NtMapViewOfSection")] = &SYSHOOKS::NtMapViewOfSection_exit;
			sysExitHooks[lookupIndex("NtGetMUIRegistryInfo")] = &SYSHOOKS::GenericScan_exit; //&SYSHOOKS::NtGetMUIRegistryInfo_exit;
			sysExitHooks[lookupIndex("NtQueryValueKey")] = &SYSHOOKS::GenericScan_exit;
			sysExitHooks[lookupIndex("NtRequestWaitReplyPort")] = &SYSHOOKS::GenericScan_exit;
			sysExitHooks[lookupIndex("NtClose")] = &SYSHOOKS::GenericScan_exit;
			sysExitHooks[lookupIndex("NtCreateSection")] = &SYSHOOKS::GenericScan_exit;
			sysExitHooks[lookupIndex("NtMapCMFModule")] = &SYSHOOKS::GenericScan_exit;
			sysExitHooks[lookupIndex("NtOpenFile")] = &SYSHOOKS::GenericScan_exit;
			sysExitHooks[lookupIndex("NtOpenKey")] = &SYSHOOKS::GenericScan_exit;
			sysExitHooks[lookupIndex("NtOpenProcessToken")] = &SYSHOOKS::GenericScan_exit;
			sysExitHooks[lookupIndex("NtOpenProcessTokenEx")] = &SYSHOOKS::GenericScan_exit;
			sysExitHooks[lookupIndex("NtOpenSection")] = &SYSHOOKS::GenericScan_exit;
			sysExitHooks[lookupIndex("NtQueryAttributesFile")] = &SYSHOOKS::GenericScan_exit;
			sysExitHooks[lookupIndex("NtQueryInformationProcess")] = &SYSHOOKS::GenericScan_exit;
			sysExitHooks[lookupIndex("NtQueryInformationToken")] = &SYSHOOKS::GenericScan_exit;
			sysExitHooks[lookupIndex("NtQuerySection")] = &SYSHOOKS::GenericScan_exit;
			//sysExitHooks[lookupIndex("")] = &SYSHOOKS::GenericScan_exit;

			// Win32k stuff (embedded ordinal)
			win32sysExitHooks[NTGDIPOLYTEXTOUTW] = &SYSHOOKS::GenericScan_exit;
			win32sysExitHooks[NTGDIDRAWSTREAM] = &SYSHOOKS::GenericScan_exit;
		}

		// BluePill
		sysEntryHooks[lookupIndex("NtDelayExecution")] = &SYSHOOKS::NtDelayexecution_entry;
		sysExitHooks[lookupIndex("NtQueryInformationProcess")] = &SYSHOOKS::NtQueryInformationProcess_exit;
		sysExitHooks[lookupIndex("NtQuerySystemInformation")] = &SYSHOOKS::NtQuerySystemInformation_exit;
		sysExitHooks[lookupIndex("NtQueryPerformanceCounter")] = &SYSHOOKS::NtQueryPerformanceCounter_exit;
		sysEntryHooks[lookupIndex("NtCreateFile")] = &SYSHOOKS::NtCreateFile_entry;
		//sysEntryHooks[lookupIndex("NtResumeThread")] = &SYSHOOKS::NtResumeThread_entry;
		sysExitHooks[lookupIndex("NtQueryDirectoryObject")] = &SYSHOOKS::NtQueryDirectoryObject_exit;
		sysExitHooks[lookupIndex("NtOpenKey")] = &SYSHOOKS::NtOpenKey_exit;
		sysExitHooks[lookupIndex("NtOpenKeyEx")] = &SYSHOOKS::NtOpenKey_exit;
		sysExitHooks[lookupIndex("NtEnumerateKey")] = &SYSHOOKS::NtEnumerateKey_exit;
		sysExitHooks[lookupIndex("NtQueryValueKey")] = &SYSHOOKS::NtQueryValueKey_exit;
		sysEntryHooks[lookupIndex("NtQueryAttributesFile")] = &SYSHOOKS::NtQueryAttributesFile_entry;
		//sysEntryHooks[lookupIndex("NtOpenDirectoryObject")] = &SYSHOOKS::NtOpenDirectoryObject_entry;
		sysExitHooks[lookupIndex("NtQueryObject")] = &SYSHOOKS::NtQueryObject_exit;
		//sysExitHooks[lookupIndex("NtGetContextThread")] = &SYSHOOKS::NtGetContextThreadHook;

		// Win32k stuff (embedded ordinal)
		win32sysExitHooks[NTUSERENUMDISPLAYDEVICES] = &SYSHOOKS::NtUserEnumDisplayDevices_exit;
		win32sysExitHooks[NTUSERFINDWINDOWSEX] = &SYSHOOKS::NtUserFindWindowEx_exit;

		// register analysis callbacks for Pin
		PIN_AddSyscallEntryFunction(&SyscallEntry, NULL);
		PIN_AddSyscallExitFunction(&SyscallExit, NULL);
	}

}