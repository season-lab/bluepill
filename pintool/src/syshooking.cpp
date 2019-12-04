#include <iostream>

#include "syshooking.h"
#include "memory.h"
#include "syshooks.h"

namespace W {
#include "windows.h"
}

extern TLS_KEY tls_key;

namespace SYSHOOKING {
	CHAR* syscallIDs[MAXSYSCALLS];

	// entries NULL by default (POD)
	syscall_hook sysEntryHooks[MAXSYSCALLS];
	syscall_hook sysExitHooks[MAXSYSCALLS];
	syscall_hook win32sysEntryHooks[MAXWIN32KSYSCALLS-0x1000];
	syscall_hook win32sysExitHooks[MAXWIN32KSYSCALLS-0x1000];

	// helpers
	VOID enumSyscalls();
	VOID registerHooks();
	VOID getArgumentsOnEntry(CONTEXT *ctx, SYSCALL_STANDARD std, int count, ...);
	int lookupIndex(const char* syscallName);


	VOID Init() {
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

	/** HELPER METHODS BEGIN HERE **/

	// ntdll parsing for syscall ordinal extraction
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
			if (memcmp(name, "Nt", 2)) continue;

			// does the signature match one of these cases?
			// 1:   mov eax, syscall_number ; mov ecx, some_value
			// 2:   mov eax, syscall_number ; xor ecx, ecx
			// 3:   mov eax, syscall_number ; mov edx, 0x7ffe0300
			// TODO remember to add one more case when we go for Windows 8+
			if (addr[0] == 0xb8 && (addr[5] == 0xb9 || addr[5] == 0x33 || addr[5] == 0xba)) {
				ADDRINT syscall_number = *(UINT32*)(addr + 1);
				ASSERT(!syscallIDs[syscall_number], "Multiple syscalls on same ordinal?");
				syscallIDs[syscall_number] = strdup(name);
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