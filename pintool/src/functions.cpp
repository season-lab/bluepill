#include "functions.h"
#include "Helper.h"
#include "HiddenElements.h"
#include "types.h"
#include "state.h"
#include "process.h"

#include <string>
#include <iostream>

using namespace std; // KTM FP

#define MAX_MAC_ADDRESS_SIZE		50
#define MAX_GETPROCADDR_ORDINAL		0x200

/* for when we fill existing fields with random stuff */
#define CHAR_SDI	's'
#define STR_GUI_1A	"W" // TODO duplicate with strdup?
#define STR_GUI_1B	"a"
#define STR_GUI_2	"WantSuppli"

const char netVendor[] = BP_NETVENDOR;
const char fakeProcess[] = BP_FAKEPROCESS;

// quick hook insertion for return address check: use it with
// library calls only (syscalls need a different treatment)
#define RETADDR_HOOK(rtn)	do { \
								RTN_InsertCall(rtn, IPOINT_BEFORE, \
								(AFUNPTR)Process::CheckRetAddrLibcall, \
								IARG_REG_VALUE, REG_STACK_PTR, IARG_END); \
							} while (0)

namespace Functions {
	// for internal use only
	static std::map<std::string, int> fMap;

	// this function populates a hook/API map that we inspect during AOT instrumentation
	void Init() {

		fMap.insert(std::pair<std::string, int>("NtDelayExecution", NTDELAYEXEC_INDEX));
		fMap.insert(std::pair<std::string, int>("NtQueryPerformanceCounter", NTQUERYPERF_INDEX));

		fMap.insert(std::pair<std::string, int>("FindFirstFile", GETFIRSTFILE_INDEX));
		fMap.insert(std::pair<std::string, int>("FindFirstFileA", GETFIRSTFILE_INDEX));
		fMap.insert(std::pair<std::string, int>("FindFirstFileW", GETFIRSTFILE_INDEX));

		fMap.insert(std::pair<std::string, int>("FindNextFile", GETFIRSTFILE_INDEX));
		fMap.insert(std::pair<std::string, int>("FindNextFileA", GETFIRSTFILE_INDEX));
		fMap.insert(std::pair<std::string, int>("FindNextFileW", GETFIRSTFILE_INDEX));

		fMap.insert(std::pair<std::string, int>("GetAdaptersInfo", GETADAPTER_INDEX));

		fMap.insert(std::pair<std::string, int>("GetSystemInfo", SYSINFO_INDEX));

		fMap.insert(std::pair<std::string, int>("GetCursorPos", GETCUR_INDEX));

		fMap.insert(std::pair<std::string, int>("getenv", GETENV_INDEX));

		fMap.insert(std::pair<std::string, int>("FindWindow", FINDWINDOW_INDEX));
		fMap.insert(std::pair<std::string, int>("FindWindowW", FINDWINDOW_INDEX));
		fMap.insert(std::pair<std::string, int>("FindWindowA", FINDWINDOW_INDEX));

		fMap.insert(std::pair<std::string, int>("WNetGetProviderName", WGETNET_INDEX));
		fMap.insert(std::pair<std::string, int>("WNetGetProviderNameW", WGETNET_INDEX));
		fMap.insert(std::pair<std::string, int>("WNetGetProviderNameA", WGETNET_INDEX));

		fMap.insert(std::pair<std::string, int>("NtClose", CLOSEH_INDEX)); // syscall was tricky, we hook it from here for now

		fMap.insert(std::pair<std::string, int>("GetKeyboardLayout", KEYB_INDEX));

		fMap.insert(std::pair<std::string, int>("GetPwrCapabilities", POWCAP_INDEX));


		fMap.insert(std::pair<std::string, int>("ChangeServiceConfigW", CHANGSERV_INDEX));

		fMap.insert(std::pair<std::string, int>("InitiateSystemShutdownExW", SHUTD_INDEX));


		fMap.insert(std::pair<std::string, int>("SetupDiGetDeviceRegistryProperty", SETUPDEV_INDEX));
		fMap.insert(std::pair<std::string, int>("SetupDiGetDeviceRegistryPropertyW", SETUPDEV_INDEX));
		fMap.insert(std::pair<std::string, int>("SetupDiGetDeviceRegistryPropertyA", SETUPDEV_INDEX));

		// TODO do we need something for Ex?
		fMap.insert(std::pair<std::string, int>("GetModuleFileName", GETMODULE_INDEX));
		fMap.insert(std::pair<std::string, int>("GetModuleFileNameA", GETMODULE_INDEX));
		fMap.insert(std::pair<std::string, int>("GetModuleFileNameW", GETMODULE_INDEX));


		fMap.insert(std::pair<std::string, int>("K32GetDeviceDriverBaseName", DEVICEBASE_INDEX));
		fMap.insert(std::pair<std::string, int>("K32GetDeviceDriverBaseNameA", DEVICEBASE_INDEX));
		fMap.insert(std::pair<std::string, int>("K32GetDeviceDriverBaseNameW", DEVICEBASE_INDEX));

		fMap.insert(std::pair<std::string, int>("GetWindowText", WINNAME_INDEX));
		fMap.insert(std::pair<std::string, int>("GetWindowTextA", WINNAME_INDEX));
		fMap.insert(std::pair<std::string, int>("GetWindowTextW", WINNAME_INDEX));

		//fMap.insert(std::pair<std::string, int>("LoadLibrary", LOADLIB_INDEX));
		fMap.insert(std::pair<std::string, int>("LoadLibraryA", LOADLIBA_INDEX));
		fMap.insert(std::pair<std::string, int>("LoadLibraryW", LOADLIBW_INDEX));
		//fMap.insert(std::pair<std::string, int>("LoadLibraryEx", LOADLIB_INDEX));
		fMap.insert(std::pair<std::string, int>("LoadLibraryExA", LOADLIBA_INDEX));
		fMap.insert(std::pair<std::string, int>("LoadLibraryExW", LOADLIBW_INDEX));

		fMap.insert(std::pair<std::string, int>("_popen", POPEN_INDEX));
		fMap.insert(std::pair<std::string, int>("_wpopen", POPEN_INDEX));
		fMap.insert(std::pair<std::string, int>("_tpopen", POPEN_INDEX));

		fMap.insert(std::pair<std::string, int>("GetDiskFreeSpaceEx", GETDISKSPACE_INDEX));
		fMap.insert(std::pair<std::string, int>("GetDiskFreeSpaceExW", GETDISKSPACE_INDEX));
		fMap.insert(std::pair<std::string, int>("GetDiskFreeSpaceExA", GETDISKSPACE_INDEX));

		fMap.insert(std::pair<std::string, int>(
			"?Get@CWbemObject@@UAGJPBGJPAUtagVARIANT@@PAJ2@Z",
			WMI_INDEX)
		);

		// timing (TODO most of these are only for logging - PUUUUH)
		fMap.insert(std::pair<std::string, int>("GetTickCount", GETTICKCOUNT_INDEX));
		fMap.insert(std::pair<std::string, int>("SetTimer", SETTIMER_INDEX));
		fMap.insert(std::pair<std::string, int>("WaitForSingleObject", WAITOBJ_INDEX));
		fMap.insert(std::pair<std::string, int>("GetSystemTimeAsFileTime", TIMEASFILE_INDEX));
		fMap.insert(std::pair<std::string, int>("IcmpCreateFile", ICMPFILE_INDEX));
		fMap.insert(std::pair<std::string, int>("IcmpSendEcho", ICMPECHO_INDEX));

		/* DEBUG HOOKS */
#if 0
		fMap.insert(std::pair<std::string, int>("RtlCompareUnicodeString", RTLSTR_INDEX));
		fMap.insert(std::pair<std::string, int>("RtlEqualUnicodeString", RTLSTR_INDEX));

		fMap.insert(std::pair<std::string, int>("wcsstr", WCSSTR_INDEX));
		fMap.insert(std::pair<std::string, int>("wcscmp", WCSCMP_INDEX));
		fMap.insert(std::pair<std::string, int>("wcsncmp", WCSCMP_INDEX));
		fMap.insert(std::pair<std::string, int>("_wcsnicmp", WCSCMP_INDEX));

		fMap.insert(std::pair<std::string, int>("strstr", STRSTR_INDEX));
		fMap.insert(std::pair<std::string, int>("strcmp", STRCMP_INDEX));
		fMap.insert(std::pair<std::string, int>("_strcmpi", STRCMP_INDEX));

		fMap.insert(std::pair<std::string, int>("CompareString", CMPSTR_INDEX));
		fMap.insert(std::pair<std::string, int>("CompareStringA", CMPSTR_INDEX));
		fMap.insert(std::pair<std::string, int>("CompareStringW", CMPSTR_INDEX));
		fMap.insert(std::pair<std::string, int>("CompareStringEx", CMPSTR_INDEX));
		fMap.insert(std::pair<std::string, int>("CompareStringExA", CMPSTR_INDEX));
		fMap.insert(std::pair<std::string, int>("CompareStringExW", CMPSTR_INDEX));
#endif
		/* END OF DEBUG HOOKS */

	}


	//scan the image and try to hook any found function specified in the map
	void AddHooks(IMG img) {

		// Pin cannot find this routine used for WMI so we define it manually
		if (IMG_Name(img).find("fastprox") != string::npos) {
			RTN tmp = RTN_CreateAt(IMG_LowAddress(img) + WMIOFFSETEXEC, "GetQuery");
			RTN_Open(tmp);
			RTN_InsertCall(tmp, IPOINT_BEFORE, (AFUNPTR)WMIExecQueryHook, IARG_FUNCARG_ENTRYPOINT_REFERENCE, 2, IARG_END);
			RTN_Close(tmp);
		}

		// iterate over functions that we want to hook/replace
		for (std::map<string, int>::iterator it = fMap.begin(),
			end = fMap.end(); it != end; ++it) {
			const char* func_name = it->first.c_str();
			RTN rtn = RTN_FindByName(img, func_name); // get pointer to the function
			if (rtn != RTN_Invalid()) {
				int index = it->second;
				RTN_Open(rtn); 	// TODO add PIN_LockClient?

				switch (index) {

				case(GETADAPTER_INDEX):
					RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)GetAdaptersInfoHookEntry,
						IARG_FUNCARG_ENTRYPOINT_REFERENCE, 0,
						IARG_FUNCARG_ENTRYPOINT_REFERENCE, 1,
						IARG_END);
					RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)GetAdaptersInfoHookExit,
						IARG_FUNCRET_EXITPOINT_VALUE,
						IARG_END);
					break;

				case(FINDWINDOW_INDEX):
					RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)FindWindowHook,
						IARG_FUNCARG_ENTRYPOINT_REFERENCE, 0,
						IARG_FUNCARG_ENTRYPOINT_REFERENCE, 1,
						IARG_END);
					break;

				case(WGETNET_INDEX):
					RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)WNetGetProviderNameHookEntry,
						IARG_FUNCARG_ENTRYPOINT_REFERENCE, 1,
						IARG_END);
					RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)WNetGetProviderNameHookExit,
						IARG_END);
					break;

				case(GETTICKCOUNT_INDEX):
					RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)timeLogHook,
						IARG_RETURN_IP,
						IARG_PTR, "GetTickCnt",
						IARG_END); // log GetTickCount
					RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)GetTickCountHook, IARG_FUNCRET_EXITPOINT_REFERENCE,
						IARG_END);
					break;

				case(SETTIMER_INDEX):
					RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)timeLogHook,
						IARG_RETURN_IP,
						IARG_PTR, "SetTimer",
						IARG_END); // log SetTimer
					RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)SetTimerHook,
						IARG_FUNCARG_ENTRYPOINT_REFERENCE, 2,
						IARG_END);
					break;

				case(WAITOBJ_INDEX):
					RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)timeLogHook,
						IARG_RETURN_IP,
						IARG_PTR, "WFSO",
						IARG_END); // log WaitForSingleObject
					RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)WaitForSingleObjectHook,
						IARG_FUNCARG_ENTRYPOINT_REFERENCE, 1,
						IARG_END);
					break;

				case(ICMPFILE_INDEX):
					RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)timeLogHook,
						IARG_RETURN_IP,
						IARG_PTR, "IcmpCrtF",
						IARG_END); // log IcmpCreateFile
					RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)IcmpCreateFileEntryHook,
						IARG_END);
					RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)IcmpCreateFileExitHook,
						IARG_END);
					break;

				case(ICMPECHO_INDEX):
					RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)timeLogHook,
						IARG_RETURN_IP,
						IARG_PTR, "IcmpSndE",
						IARG_END); // log IcmpSendEcho
					RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)IcmpSendEchoHook,
						IARG_FUNCARG_ENTRYPOINT_REFERENCE, 7,
						IARG_END);
					break;

				case(GETDISKSPACE_INDEX):
					RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)GetDiskFreeSpaceHookEntry,
						IARG_RETURN_IP,
						IARG_FUNCARG_ENTRYPOINT_REFERENCE, 1,
						IARG_FUNCARG_ENTRYPOINT_REFERENCE, 2,
						IARG_FUNCARG_ENTRYPOINT_REFERENCE, 3,
						IARG_END);
					RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)GetDiskFreeSpaceHookExit,
						IARG_END);
					break;

				case(GETFIRSTFILE_INDEX):
					RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)FindFirstFileHook,
						IARG_FUNCARG_ENTRYPOINT_REFERENCE, 0,
						IARG_END);
					break;

				case(TIMEASFILE_INDEX):
					RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)logGetSystemTimeAsFileTime,
						IARG_RETURN_IP,
						IARG_END);
					break;

				case(POPEN_INDEX):
					RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)_popenHook,
						IARG_FUNCARG_ENTRYPOINT_REFERENCE, 0,
						IARG_END);
					break;

				case(GETENV_INDEX):
					RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)GetEnvHookEntry,
						IARG_FUNCARG_ENTRYPOINT_REFERENCE, 0,
						IARG_END);
					break;

				case(LOADLIBA_INDEX):
					RETADDR_HOOK(rtn); // TODO inserted just for testing purposes
					RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)LoadLibraryAHook,
						IARG_FUNCARG_ENTRYPOINT_REFERENCE, 0,
						IARG_INST_PTR,
						IARG_END);
					break;

				case(LOADLIBW_INDEX):
					RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)LoadLibraryWHook,
						IARG_FUNCARG_ENTRYPOINT_REFERENCE, 0,
						IARG_INST_PTR,
						IARG_END);
					break;

				case(DEVICEBASE_INDEX):
					RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)GetDeviceDriverBaseNameHookEntry,
						IARG_FUNCARG_ENTRYPOINT_REFERENCE, 1,
						IARG_END);
					RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)GetDeviceDriverBaseNameHookExit,
						IARG_END);
					break;

				case(WINNAME_INDEX):
					RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)GetWindowTextHookEntry,
						IARG_FUNCARG_ENTRYPOINT_REFERENCE, 1,
						IARG_END);
					RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)GetWindowTextHookExit,
						IARG_END);
					break;

				case(GETMODULE_INDEX):
					RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)GetModuleFileNameHookEntry,
						IARG_FUNCARG_ENTRYPOINT_REFERENCE, 1,
						IARG_END);
					RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)GetModuleFileNameHookExit,
						IARG_END);
					break;

				case(SETUPDEV_INDEX):
					RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)SetupDiGetDeviceRegistryPropertyHookEntry,
						IARG_FUNCARG_ENTRYPOINT_REFERENCE, 4,
						IARG_END);
					RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)SetupDiGetDeviceRegistryPropertyHookExit,
						IARG_FUNCRET_EXITPOINT_VALUE,
						IARG_END);
					break;

				case(CLOSEH_INDEX):
					if (_debugger) {
						RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)CloseHandleHookEntry,
							IARG_FUNCARG_ENTRYPOINT_REFERENCE, 0,
							IARG_END);
						RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)CloseHandleHookExit,
							IARG_FUNCRET_EXITPOINT_REFERENCE,
							IARG_END);
					}
					break;

				case(GETCUR_INDEX):
					RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)GetCursorPosHookEntry,
						IARG_RETURN_IP,
						IARG_FUNCARG_ENTRYPOINT_REFERENCE, 0,
						IARG_END);
					RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)GetCursorPosHookExit,
						IARG_END);
					break;

				case(KEYB_INDEX):
					RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)GetKeyboardLayoutHookExit,
						IARG_FUNCRET_EXITPOINT_REFERENCE,
						IARG_END);
					break;

				case(SYSINFO_INDEX):
					RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)GetSystemInfoHookEntry,
						IARG_FUNCARG_ENTRYPOINT_REFERENCE, 0,
						IARG_END);
					RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)GetSystemInfoHookExit,
						IARG_END);
					break;

				case(POWCAP_INDEX):
					RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)GetPwrCapabilitiesHookEntry,
						IARG_FUNCARG_ENTRYPOINT_REFERENCE, 0,
						IARG_END);
					RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)GetPwrCapabilitiesHookExit,
						IARG_END);
					break;

				case(WMI_INDEX):
					RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)WMIQueryHookEntry,
						IARG_FUNCARG_ENTRYPOINT_REFERENCE, 1,
						IARG_FUNCARG_ENTRYPOINT_REFERENCE, 3,
						IARG_END);
					RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)WMIQueryHookExit,
						IARG_END);
					break;

				case(CHANGSERV_INDEX):
					RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)ChangeServiceConfigWHook,
						IARG_FUNCARG_ENTRYPOINT_REFERENCE, 0,
						IARG_END);
					break;

				case(SHUTD_INDEX):
					RTN_Replace(rtn, (AFUNPTR)InitiateSystemShutdownExWHook);
					break;


					/****************** DEBUG HOOK **************/

				case(CMPSTR_INDEX):
					RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)CompareStringHook,
						IARG_FUNCARG_ENTRYPOINT_REFERENCE, 2,
						IARG_FUNCARG_ENTRYPOINT_REFERENCE, 4,
						IARG_END);
					break;

				case(RTLSTR_INDEX):
					RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)RtlCompareUnicodeStringHook,
						IARG_FUNCARG_ENTRYPOINT_REFERENCE, 0,
						IARG_FUNCARG_ENTRYPOINT_REFERENCE, 1,
						IARG_END);
					break;

				case(WCSSTR_INDEX):
					RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)wcsstrHook,
						IARG_FUNCARG_ENTRYPOINT_REFERENCE, 0,
						IARG_FUNCARG_ENTRYPOINT_REFERENCE, 1,
						IARG_END);
					break;

				case(WCSCMP_INDEX):
					RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)wcscmpHook,
						IARG_FUNCARG_ENTRYPOINT_REFERENCE, 0,
						IARG_FUNCARG_ENTRYPOINT_REFERENCE, 1,
						IARG_END);
					break;

				case(STRSTR_INDEX):
					RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)strstrHook,
						IARG_FUNCARG_ENTRYPOINT_REFERENCE, 0,
						IARG_FUNCARG_ENTRYPOINT_REFERENCE, 1,
						IARG_END);
					break;

				case(STRCMP_INDEX):
					RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)strcmpHook,
						IARG_FUNCARG_ENTRYPOINT_REFERENCE, 0,
						IARG_FUNCARG_ENTRYPOINT_REFERENCE, 1,
						IARG_END);
					break;

					// log syscalls for timing artifacts
				case(NTDELAYEXEC_INDEX):
					RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)timeLogHook,
						IARG_RETURN_IP,
						IARG_PTR, "NtDelayEx",
						IARG_END); //NtDelayExecuton
					break;

				case(NTQUERYPERF_INDEX):
					RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)timeLogHook,
						IARG_RETURN_IP,
						IARG_PTR, "NtQPerfC",
						IARG_END); // NtQueryPerformanceCounter
					break;
				}
				RTN_Close(rtn);
			}
		}
	}

} /*** END OF Functions NAMESPACE ***/


/*** HOOKS begin here ***/

VOID GetAdaptersInfoHookEntry(PIP_ADAPTER_INFO *adapInfo, W::PULONG *size) {

	ACTIVE_HOOK(EN_GetAdaptersInfo);

	LOG_AR("[GetAdaptersInfo] - MAC address check");
	
	FetchHookTLS;
	State::hookEntryArgsTLS::getAdaptersInfo *pc = &in->_getAdaptersInfo;
	pc->macStruct = *adapInfo;
	pc->macSizeStruct = *size;
	pc->macSizeStructInitial = **size;	

}

VOID GetAdaptersInfoHookExit(ADDRINT ret) {


	ACTIVE_HOOK(EN_GetAdaptersInfo);

	FetchHookTLS;
	State::hookEntryArgsTLS::getAdaptersInfo *pc = &in->_getAdaptersInfo;
	PIP_ADAPTER_INFO adapInfo = pc->macStruct;
	W::PULONG size = pc->macSizeStruct;
	W::ULONG preSize = pc->macSizeStructInitial;

	if (ret != 0 || preSize == 0 || preSize < *size || adapInfo->AddressLength == 0)
		return;
	
	while (adapInfo != nullptr) {

		if (adapInfo->AddressLength > MAX_MAC_ADDRESS_SIZE) return; //FP: avoid vmprotect 3.2 memory corrupt
		if (adapInfo->AddressLength == 6 && (!memcmp("\x08\x00\x27", adapInfo->Address, 3) ||
			!memcmp("\x00\x05\x69", adapInfo->Address, 3) || !memcmp("\x00\x0c\x29", adapInfo->Address, 3) ||
			!memcmp("\x00\x1c\x14", adapInfo->Address, 3) || !memcmp("\x00\x50\x56", adapInfo->Address, 3))) {
			memcpy(adapInfo->Address, BP_MAC_VENDOR, 3); // patch with dummy MAC
			break;
		}
		adapInfo = adapInfo->Next;
	}
	
}

VOID FindWindowHook(W::LPCTSTR* path1, W::LPCTSTR* path2) {

	ACTIVE_HOOK(EN_FindWindow);

	char value[PATH_BUFSIZE] = { 0 };
	if (path1 != NULL && *path1 != NULL && (char*)*path1 != "") {	
		GET_STR_TO_UPPER((char*)*path1, value, PATH_BUFSIZE);

		if (HiddenElements::shouldHideWindowStr(value)) {
			//LOG_EVASION("[FindWindow] - %s", value);
			*path1 = STR_GUI_1A;
			return;
		}

		memset(value, 0, sizeof(value));
		GET_WSTR_TO_UPPER(*path1, value, PATH_BUFSIZE);

		if (HiddenElements::shouldHideWindowStr(value)) {
			//LOG_EVASION("[FindWindow] - %s", value);
			//W::LPCTSTR a = "a";
			//*path1 = a;
			*path1 = STR_GUI_1B;
			return;
		}
	}

	// test on path2
	if (!(path2 != NULL && *path2 != NULL && (char*)*path2 != "")) return;
	
	memset(value, 0, sizeof(value));
	GET_STR_TO_UPPER((char*)*path2, value, PATH_BUFSIZE);

	if (HiddenElements::shouldHideWindowStr(value)) goto FIX2;

	memset(value, 0, sizeof(value));
	GET_WSTR_TO_UPPER(*path2, value, PATH_BUFSIZE);

	if (HiddenElements::shouldHideWindowStr(value)) goto FIX2;

	return;

FIX2:
	//LOG_EVASION("[FindWindow] - %s", value);
	*path2 = STR_GUI_2;

}

VOID WNetGetProviderNameHookEntry(W::LPTSTR* buffer) {

	ACTIVE_HOOK(EN_WNetGetProviderName);

	FetchHookTLS;
	in->buf = *buffer;

}

VOID WNetGetProviderNameHookExit() {

	ACTIVE_HOOK(EN_WNetGetProviderName);

	//ProcInfo *in = ProcInfo::getInstance();
	FetchHookTLS;
	W::LPTSTR buffer = in->buf;

	if (buffer == NULL) return;

	char value[PATH_BUFSIZE];

	GET_WSTR_TO_UPPER(buffer, value, PATH_BUFSIZE);

	if (strstr(value, "VIRTUALBOX") != NULL || strstr(value, "VBOX") != NULL || strstr(value, "ORACLE") != NULL) {
		LOG_AR("[WNetGPN] - %s", value);
		for (int i = 0; i < sizeof(netVendor); ++i) // sizeof is fine :-)
			in->buf[i*2] = netVendor[i]; // WCHAR
		return;
	}

	memset(value, 0, sizeof(value));

	GET_STR_TO_UPPER(buffer, value, PATH_BUFSIZE);

	if (strstr(value, "VIRTUALBOX") != NULL || strstr(value, "VBOX") != NULL || strstr(value, "ORACLE") != NULL) {
		for (int i = 0; i < sizeof(netVendor); ++i)
			in->buf[i*2] = netVendor[i]; // char
	}
	
}



VOID GetTickCountHook(W::DWORD* ret) {

	ACTIVE_HOOK(EN_GetTickCount);

	FetchTimeState;
	tinfo->tick += 30 + tinfo->sleepMsTick;
	tinfo->sleepMsTick = 0;
	*ret = tinfo->tick;

}

VOID SetTimerHook(W::UINT *time) {

	ACTIVE_HOOK(EN_SetTimer);

	if (*time == INFINITE) return; // we do not fast-forward this pattern
	////LOG_EVASION("[EVASION?] SetTimer called! -> %u", *time);


	FetchTimeState;
	tinfo->sleepMs += *time;
	tinfo->sleepMsTick += *time;

	// reset sleep value
	*time = BP_TIMER;

}

VOID WaitForSingleObjectHook(W::DWORD *time) {

	ACTIVE_HOOK(EN_WaitForSingleObject);

	if (*time == INFINITE) return; // we do not fast-forward this pattern
	////LOG_EVASION("[EVASION?] WaitForSingleObject called! -> %u", *time);

	FetchTimeState;
	tinfo->sleepMs += *time;
	tinfo->sleepMsTick += *time;

	*time = BP_TIMER;

}

VOID IcmpCreateFileEntryHook() {

	ACTIVE_HOOK(EN_IcmpCreateFile);

	FetchTimeState;
	// special treatment for this call to avoid instabilities
	// (perhaps we can drop this once we select by call sites)
	tinfo->sleepTime = BP_ICMP_CREATE;

}

VOID IcmpCreateFileExitHook() {

	ACTIVE_HOOK(EN_IcmpCreateFile);

	FetchTimeState;
	tinfo->sleepTime = 0;

}

VOID IcmpSendEchoHook(W::DWORD *time) {

	ACTIVE_HOOK(EN_IcmpSendEcho);

	//LOG_EVASION("[IcmpSendEcho] - %u", *time);
	FetchTimeState;
	tinfo->sleepMs += *time;
	tinfo->sleepMsTick += *time;

	//reset timer
	*time = BP_ICMP_ECHO;

}


VOID GetDiskFreeSpaceHookEntry(ADDRINT retAddr, W::PULARGE_INTEGER *lpFreeBytesAvailable, W::PULARGE_INTEGER *lpTotalNumberOfBytes,
	W::PULARGE_INTEGER *lpTotalNumberOfFreeBytes) {

	ACTIVE_HOOK(EN_GetDiskFreeSpaceEx);

	//ProcInfo *pc = ProcInfo::getInstance();
	FetchHookTLS;
	in->getDiskFreeSpaceRetAddr = retAddr; // for logging purposes
	State::hookEntryArgsTLS::getDiskFreeSpace *pc = &in->_getDiskFreeSpace;
	pc->lpFreeBytesAvailable = *lpFreeBytesAvailable;
	pc->lpTotalNumberOfBytes = *lpTotalNumberOfBytes;
	pc->lpTotalNumberOfFreeBytes = *lpTotalNumberOfFreeBytes;

}

VOID GetDiskFreeSpaceHookExit() {

	ACTIVE_HOOK(EN_GetDiskFreeSpaceEx);

	FetchHookTLS;
	State::hookEntryArgsTLS::getDiskFreeSpace *pc = &in->_getDiskFreeSpace;
	if (pc->lpFreeBytesAvailable != NULL)
		pc->lpFreeBytesAvailable->QuadPart = 1073741824000;
	if (pc->lpTotalNumberOfBytes != NULL)
		pc->lpTotalNumberOfBytes->QuadPart = 1073741824000;
	if (pc->lpTotalNumberOfFreeBytes != NULL)
		pc->lpTotalNumberOfFreeBytes->QuadPart = 1073741824000;

	// TODO add check IsAddrFromWindowsDLL() on in->getDiskFreeSpaceRetAddr for log
}

// TODO use generic pointer and then distinguish string type (char or wchar_t)
// This unfortunately applies to all the other functions in this file taking
// string parameters. At some point we will get it right like here :)
VOID FindFirstFileHook(W::LPCTSTR *path) {

	ACTIVE_HOOK(EN_FindFirstFile);

	if (path == NULL || *path == NULL || (void*)*path == (void*)0xffffffff) {
		return;
	}

	char value[PATH_BUFSIZE];

	GET_STR_TO_UPPER(*path, value, PATH_BUFSIZE);
	if (HiddenElements::shouldHideGenericFileNameStr(value)) {
		LOG_AR("[FindFirstFile] - %s", value);
		const char** _path = (const char**)path;
		*_path = BP_FAKEFILE;
		return;
	}

	memset(value, 0, sizeof(value));
	GET_WSTR_TO_UPPER(*path, value, PATH_BUFSIZE);
	if (HiddenElements::shouldHideGenericFileNameStr(value)) {
		LOG_AR("[FindFirstFile] - %s", value);
		const wchar_t** _path = (const wchar_t**)path;
		*_path = BP_FAKEFILE_W;
		return;
	}

}


VOID _popenHook(const char **command) {

	ACTIVE_HOOK(EN__popen);

	if (*command != NULL) {
		if (strstr(*command, "size") == NULL) {
			LOG_AR("[Popen] - %s", *command);
			*command = BP_POPEN;
		}
	}

}

VOID LoadLibraryAHook(const char **lib) { // TODO use HiddenElements

	ACTIVE_HOOK(EN_LoadLibrary);

	FetchHookTLS; // TODO added only for testing purposes
	if (in->retAddrInDLL) {
		LOG_AR("Loadlibrary within Windows DLL! Happening at %x in:\n==> %s", in->retAddr, (const char*)in->retAddrInDll_data);
	}
	else {
		LOG_AR("Loadlibrary likely from user code!");
	}


	if (lib == NULL || *lib == NULL) return;

	char value[PATH_BUFSIZE];
	GET_STR_TO_UPPER(*lib, value, PATH_BUFSIZE);

	if (strstr(value, "VIRTUALBOX") != NULL || strstr(value, "VBOX") != NULL || strstr(value, "HOOK") != NULL) {
		//LOG_EVASION("[LoadLibraryA] - %s", value);
		*lib = BP_FAKEDLL;
	}

}

VOID LoadLibraryWHook(const wchar_t **lib) { // TODO use HiddenElements

	ACTIVE_HOOK(EN_LoadLibrary);

	if (lib == NULL || *lib == NULL) return;

	char value[PATH_BUFSIZE];
	GET_WSTR_TO_UPPER(*lib, value, PATH_BUFSIZE);

	if (strstr(value, "VIRTUALBOX") != NULL || strstr(value, "VBOX") != NULL || strstr(value, "HOOK") != NULL) {
		//LOG_EVASION("[LoadLibrary] - %s", value);
		*lib = BP_FAKEDLL_W;
		return;
	}

}

VOID GetDeviceDriverBaseNameHookEntry(W::LPTSTR *lpBaseName) { // TODO

	ACTIVE_HOOK(EN_K32GetDeviceDriverBaseName);

	FetchHookTLS;
	in->driverBaseName = *lpBaseName;

}

VOID GetDeviceDriverBaseNameHookExit() {

	ACTIVE_HOOK(EN_K32GetDeviceDriverBaseName);

	FetchHookTLS;

	if (in->driverBaseName == NULL || *in->driverBaseName == NULL) return;


	char value[PATH_BUFSIZE];
	
	GET_STR_TO_UPPER(in->driverBaseName, value, PATH_BUFSIZE);
	if (strstr(value, "VBOX") != NULL) {
		LOG_AR("[GetDeviceDBN] - %s", value);
		memcpy(in->driverBaseName, BP_FAKEDRV, sizeof(BP_FAKEDRV));
		return;
	}

	memset(value, 0, sizeof(value));
	GET_WSTR_TO_UPPER(in->driverBaseName, value, PATH_BUFSIZE);
	if (strstr(value, "VBOX") != NULL) {
		LOG_AR("[GetDeviceDBN] - %s", value);
		memcpy(in->driverBaseName, BP_FAKEDRV_W, sizeof(BP_FAKEDRV_W));
		return;
	}

}

VOID GetWindowTextHookEntry(W::LPTSTR *lpString) {

	ACTIVE_HOOK(EN_GetWindowText);

	FetchHookTLS;
	in->windowName = *lpString;

}

VOID GetWindowTextHookExit() {

	ACTIVE_HOOK(EN_GetWindowText);

	FetchHookTLS;
	if (in->windowName == NULL || *in->windowName == NULL) return;

	char value[PATH_BUFSIZE];
	
	GET_WSTR_TO_UPPER(in->windowName, value, PATH_BUFSIZE);
	if (strstr(value, "VBOX") != NULL) {
		memset(in->windowName, 0, W::lstrlenW((W::LPCWSTR)in->windowName));
		memcpy(in->windowName, L"ex", sizeof(L"ex"));
		return;
	}

	memset(value, 0, sizeof(value));
	GET_STR_TO_UPPER(in->windowName, value, PATH_BUFSIZE);
	if (strstr(value, "VBOX") != NULL) {
		memset(in->windowName, 0, W::lstrlenA((const char*)in->windowName));
		memcpy(in->windowName, "ex", sizeof("ex")); // todo ANSI :-/
		return;
	}

}


VOID GetModuleFileNameHookEntry(W::LPTSTR *name) {

	ACTIVE_HOOK(EN_GetModuleFileName);

	FetchHookTLS;
	in->modName = *name;

}

VOID GetModuleFileNameHookExit() { // TODO we don't do anything about it? FIX THIS ASAP

	ACTIVE_HOOK(EN_GetModuleFileName);

	FetchHookTLS;
	if (in->modName == NULL) return;

	char value[PATH_BUFSIZE];

	GET_WSTR_TO_UPPER(in->modName, value, PATH_BUFSIZE);

	if (strstr(value, "VBOX") != NULL || strstr(value, "PIN") != NULL) goto FIX; 

	memset(value, 0, sizeof(value));
	GET_STR_TO_UPPER(in->modName, value, PATH_BUFSIZE);
	if (strstr(value, "VBOX") != NULL || strstr(value, "PIN") != NULL) goto FIX;

	return;

FIX:
	return;
	// DCD TODO???
	LOG_AR("[GetModuleFileName] - %s", value);
}

VOID SetupDiGetDeviceRegistryPropertyHookEntry(W::PBYTE *buffer) {

	ACTIVE_HOOK(EN_SetupDiGetDeviceRegistryProperty);

	FetchHookTLS;
	in->devBuff = *buffer;

}

VOID SetupDiGetDeviceRegistryPropertyHookExit(ADDRINT ret) {

	ACTIVE_HOOK(EN_SetupDiGetDeviceRegistryProperty);

	if ((W::BOOL)ret != TRUE) return;

	FetchHookTLS;
	if (in->devBuff == NULL || *in->devBuff == NULL) return; // LPTSTR stype
	
	char value[PATH_BUFSIZE];
	GET_WSTR_TO_UPPER(in->devBuff, value, PATH_BUFSIZE);

	if (strstr(value, "VBOX") != NULL || strstr(value, "VMWARE") != NULL) {
		LOG_AR("[SDGDRP] - %s", value);
		char* tmp = (char*)in->devBuff;
		size_t len = strlen(value);
		memset(tmp, 0, 2*(len+1)); // +1 unnecessary?
		for (size_t i = 0; i < len; i++) {
			tmp[2*i] = CHAR_SDI;
		}
	}

	memset(value, 0, sizeof(value));
	GET_STR_TO_UPPER(in->devBuff, value, PATH_BUFSIZE);
	if (strstr(value, "VBOX") != NULL || strstr(value, "VMWARE") != NULL) {
		LOG_AR("[SDGDRP] - %s", value);
		char* tmp = (char*)in->devBuff;
		size_t len = strlen(value);
		memset(tmp, 0, len); // last byte is already 0
		for (size_t i = 0; i < len; i++) {
			tmp[i] = CHAR_SDI;
		}
	}
}

VOID CloseHandleHookEntry(W::HANDLE *handle) {

	ACTIVE_HOOK(EN_NtClose);
	OBJECT_HANDLE_FLAG_INFORMATION flags;
	flags.ProtectFromClose = 0;
	flags.Inherit = 0;
	
	if (W::NtQueryObject(*handle, (W::OBJECT_INFORMATION_CLASS)4, &flags, sizeof(OBJECT_HANDLE_FLAG_INFORMATION), 0) >= 0) {
		if (flags.ProtectFromClose) {
			//STATUS_HANDLE_NOT_CLOSABLE;
			LOG_AR("[CloseHandle-HNC] - STATUS_HANDLE_NOT_CLOSABLE");
			FetchHookTLS;
			in->NtCloseFlag = 1;
			W::HANDLE ret = W::CreateMutex(NULL, FALSE, BP_MUTEX);
			*handle = ret;
		}
	}
	else {
		//STATUS_INVALID_HANDLE;
		LOG_AR("[CloseHandle-I] - STATUS_INVALID_HANDLE");
		//ProcInfo *in = ProcInfo::getInstance();
		FetchHookTLS;
		in->NtCloseFlag = 2;
		W::HANDLE ret = W::CreateMutex(NULL, FALSE, BP_MUTEX);
		*handle = ret;
	}

}

VOID CloseHandleHookExit(W::BOOL *ret) {

	ACTIVE_HOOK(EN_NtClose);

	//ProcInfo *in = ProcInfo::getInstance();
	FetchHookTLS;
	//STATUS_HANDLE_NOT_CLOSABLE;
	if (in->NtCloseFlag == 1)
		*ret = 0;
	//STATUS_INVALID_HANDLE;
	else if (in->NtCloseFlag == 2) {
		W::SetLastError(ERROR_INVALID_HANDLE);
		*ret = CODEFORINVALIDHANDLE;
	}

}

VOID GetCursorPosHookEntry(ADDRINT retAddr, W::LPPOINT *point) {

	ACTIVE_HOOK(EN_GetCursorPos);

	// TODO check on libraries?
	FetchHookTLS;
	in->cursorPoint = *point;

}

VOID GetCursorPosHookExit() {

	ACTIVE_HOOK(EN_GetCursorPos);

	FetchHookTLS;
	if (in->cursorPoint == NULL) return;
	W::LPPOINT point = in->cursorPoint;
	point->x = rand() % 500;
	point->y = rand() % 500;

}

VOID GetKeyboardLayoutHookExit(W::HKL* ret) {

	ACTIVE_HOOK(EN_GetKeyboardLayout);

	LOG_AR("[GetKeyboardLayout-lib] - from library");

	W::HKL fix = (W::HKL)BP_HKL_LAYOUT;
	*ret = fix;
	
}

VOID GetSystemInfoHookEntry(W::LPSYSTEM_INFO *lpSystemInfo) {

	ACTIVE_HOOK(EN_GetSystemInformation);

	FetchHookTLS;
	in->sysInfo = *lpSystemInfo;

}

VOID GetSystemInfoHookExit() {

	FetchHookTLS;
	W::LPSYSTEM_INFO info = in->sysInfo;

	info->dwNumberOfProcessors = BP_NUMCORES;

}

VOID GetPwrCapabilitiesHookEntry(W::PSYSTEM_POWER_CAPABILITIES *lpspc) {

	ACTIVE_HOOK(EN_GetPwrCapabilities);
	
	FetchHookTLS;
	in->powerCap = *lpspc;

}

VOID GetPwrCapabilitiesHookExit() {
	
	FetchHookTLS;
	W::PSYSTEM_POWER_CAPABILITIES lpspc = in->powerCap;

	if (lpspc == nullptr) return;

	LOG_AR("[GetPwrCapabilities]");

	lpspc->SystemS1 = TRUE;
	lpspc->SystemS2 = TRUE;
	lpspc->SystemS3 = TRUE;
	lpspc->SystemS4 = TRUE;
	lpspc->ThermalControl = TRUE;
	
}

VOID WMIQueryHookEntry(W::LPCWSTR *query, W::VARIANT **var) {

	FetchHookTLS;
	State::hookEntryArgsTLS::wmiQuery *pc = &in->_wmiQuery;
	pc->varpt = *var;
	pc->queryWMI = *query;

}

VOID WMIQueryHookExit() {

	FetchHookTLS;
	State::hookEntryArgsTLS::wmiQuery *pc = &in->_wmiQuery;
	WMI_Patch(pc->queryWMI, pc->varpt);

}

VOID ChangeServiceConfigWHook(W::SC_HANDLE *hService) {

	*hService = NULL;

}

VOID GetEnvHookEntry(CHAR** var) {

	if (var == NULL || *var == NULL) return;

	char value[PATH_BUFSIZE];
	GET_STR_TO_UPPER(*var, value, PATH_BUFSIZE);

	W::DWORD oldp;
	W::VirtualProtect(*var, strlen(*var), PAGE_READWRITE, &oldp);
	memset(*var, 0, strlen(*var));
	W::VirtualProtect(*var, strlen(*var), oldp, &oldp);
	
}

/** REPLACEMENT FUNCTIONS **/

// this one was used by Olympic Destroyer
BOOL InitiateSystemShutdownExWHook(W::LPSTR lpMachineName, 
	W::LPSTR lpMessage, W::DWORD dwTimeout, W::BOOL bForceAppsClosed,
	W::BOOL bRebootAfterShutdown, W::DWORD dwReason) {
	return TRUE;
}


/*LOG SANDBOX*/

VOID GetProcAddrHookEntry(W::LPCSTR *procName) {

	ACTIVE_HOOK(EN_GetProcAddr);

	if (procName == nullptr || *procName == nullptr) return;

	if ((void*)*procName < (void*)MAX_GETPROCADDR_ORDINAL) return; //only for ordinals, max ordinals supported??

	char value[PATH_BUFSIZE];
	GET_STR_TO_UPPER(*procName, value, PATH_BUFSIZE);

	//LOG_SUSPICIOUS("[GetProcAddr] - [%s]", value);

}

VOID GetModuleHandleAHookEntry(W::LPCSTR *modName) {
	
	ACTIVE_HOOK(EN_GetModHand);

	if (modName == nullptr || *modName == nullptr) return;

	char value[PATH_BUFSIZE];
	GET_STR_TO_UPPER(*modName, value, PATH_BUFSIZE);

	//LOG_SUSPICIOUS("[GetModuleHandle] - [%s]", value);

}

VOID GetModuleHandleWHookEntry(W::LPCSTR *modName) {

	ACTIVE_HOOK(EN_GetModHand);

	if (modName == nullptr || *modName == nullptr) return;

	char value[PATH_BUFSIZE];
	GET_WSTR_TO_UPPER(*modName, value, PATH_BUFSIZE);

	//LOG_SUSPICIOUS("[GetModuleHandle] - [%s]", value);

}


VOID WMIExecQueryHook(W::TCHAR **Query) {

	char value[PATH_BUFSIZE] = { 0 };

	GET_WSTR_TO_UPPER((char*)*Query, value, PATH_BUFSIZE);
	LOG_AR("[WMI-Query] - %s", value);

}

/*********************	DEBUG	 **************************/

VOID CompareStringHook(W::LPCTSTR *s1, W::LPCTSTR *s2) {

	ACTIVE_HOOK(EN_CompareString);

	if (s1 == NULL || s2 == NULL || *s1 == NULL || *s2 == NULL)
		return;
	if (W::lstrlen(*s1) != 1 && W::lstrlen(*s2) != 1) {
		cout << "CMP1 -> " << *s1 << "   " << *s2 << endl;
	}

}

VOID RtlCompareUnicodeStringHook(W::PCUNICODE_STRING *s1, W::PCUNICODE_STRING *s2) {

	ACTIVE_HOOK(EN_RtlCompareUnicodeString);

	if (s1 == NULL || s2 == NULL || *s1 == NULL || *s2 == NULL)
		return;
	char value[PATH_BUFSIZE];
	char value1[PATH_BUFSIZE];

	GET_STR_TO_UPPER((**s1).Buffer, value, PATH_BUFSIZE);
	GET_STR_TO_UPPER((**s2).Buffer, value1, PATH_BUFSIZE);
	cout << "RTL: " << value << "   " << value1 << endl;
	//wcout << "RTL: " << (**s1).Buffer << "   " << (**s2).Buffer << endl;

}

VOID wcsstrHook(wchar_t** wcs1, const wchar_t** wcs2) {

	ACTIVE_HOOK(EN_wcsstr);

	char value[PATH_BUFSIZE];
	char value1[PATH_BUFSIZE];

	GET_STR_TO_UPPER(*wcs1, value, PATH_BUFSIZE);
	GET_STR_TO_UPPER(*wcs2, value1, PATH_BUFSIZE);
	cout << "wcs: " << value << "   " << value1 << endl;
	//cout << ": " << *wcs1 << "    " << *wcs2 << endl;

}

VOID wcscmpHook(wchar_t** wcs1, const wchar_t** wcs2) {

	ACTIVE_HOOK(EN_wcscmp);

	char value[PATH_BUFSIZE];
	char value1[PATH_BUFSIZE];

	GET_STR_TO_UPPER(*wcs1, value, PATH_BUFSIZE);
	GET_STR_TO_UPPER(*wcs2, value1, PATH_BUFSIZE);
	cout << "wcscmp: " << value << "   " << value1 << endl;
	//cout << "wcscmp: " << *wcs1 << "    " << *wcs2 << endl;

}

VOID strstrHook(char** wcs1, const char** wcs2) {

	ACTIVE_HOOK(EN_strstr);

	cout << "strstr: " << *wcs1 << "    " << *wcs2 << endl;

}

VOID strcmpHook(char** wcs1, const char** wcs2) {

	ACTIVE_HOOK(EN_strcmp);

	cout << "strcmp: " << *wcs1 << "    " << *wcs2 << endl;

}

VOID timeLogHook(ADDRINT retAddr, const char* funName) {
	/*
	if (ProcInfo::getInstance()->isInsideMainIMG(retAddr)) {
		//LOG_EVASION("[%s] - *", funName);
	}
	*/
}

VOID logGetSystemTimeAsFileTime(ADDRINT retAddr) {
	static int logCounter = 0;
#define logGetSystemTimeAsFileTime_COUNT	20
	/*
	if (ProcInfo::getInstance()->isInsideMainIMG(retAddr)) {
		if (logCounter % logGetSystemTimeAsFileTime_COUNT == 0) {
			//LOG_EVASION("[GetSTAsFT] - *");
		}
		logCounter = (logCounter + 1) % logGetSystemTimeAsFileTime_COUNT;
	}
	*/
#undef logGetSystemTimeAsFileTime_COUNT
}