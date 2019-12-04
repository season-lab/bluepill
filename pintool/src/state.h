#pragma once

#include "pin.H" // has to go before winheaders.h or everything will break... meh!
#include "winheaders.h"

namespace State {

	void init();

	struct timeInfo {
		W::DWORD sleepMs; // WaitForSingleObjectHook, SYSHOOKS::NtDelayexecution_entry, INS_patchRtdsc_exit
		W::DWORD sleepMsTick; // GetTickCount, WaitForSingleObjectHook, SYSHOOKS::NtDelayexecution_entry, SYSHOOKS::NtQueryPerformanceCounter_exit
		W::SHORT sleepTime; // NtDelayexecution, IcmpCreateFileEntryHook
		W::DWORD lastMs; // SYSHOOKS::NtDelayexecution_entry
		W::DWORD numLastMs; // SYSHOOKS::NtDelayexecution_entry
		W::DWORD lastMs2; // SYSHOOKS::NtQueryPerformanceCounter
		W::DWORD numLastMs2; // SYSHOOKS::NtQueryPerformanceCounter
		W::DWORD tick; // GetTickCountHook - REQUIRES INITIALIZATION
		UINT64 _edx_eax; // INS_patchRtdsc_exit - REQUIRES INITIALIZATION
		UINT32 _eax; // INS_patchRtdsc_exit
		UINT32 _edx; // INS_patchRtdsc_exit
	};

	struct globalState {
		timeInfo _timeInfo;
		W::SHORT ntQueryCounter;
		W::SHORT flagStep;
		W::BOOL waitForDebugger;
	};

	// union would have been great, but how can we rule out nested hooks?
	struct hookEntryArgsTLS {
		ADDRINT cpuid_eax; // INS_patchCpuid_entry
		W::LPBYTE dataQuery; // RegQueryValueEx
		W::LPTSTR buf; // WNetGetProviderNameHookEntry
		W::LPPROCESSENTRY32 lp; // Process32NextEntry
		struct getDiskFreeSpace { // GetDiskFreeSpaceHookEntry
			W::PULARGE_INTEGER lpFreeBytesAvailable;
			W::PULARGE_INTEGER lpTotalNumberOfBytes;
			W::PULARGE_INTEGER lpTotalNumberOfFreeBytes;
		} _getDiskFreeSpace;
		W::LPTSTR driverBaseName; // GetDeviceDriverBaseNameHookEntry
		W::LPTSTR windowName; // GetWindowTextHookEntry
		W::LPTSTR modName; // GetModuleFileNameHookEntry
		struct getAdaptersInfo {  // GetAdaptersInfoHookEntry
			PIP_ADAPTER_INFO macStruct;
			W::PULONG  macSizeStruct;
			W::ULONG  macSizeStructInitial;
		} _getAdaptersInfo;
		W::PBYTE devBuff; // SetupDiGetDeviceRegistryPropertyHookEntry
		W::INT NtCloseFlag; // CloseHandleHookEntry
		W::LPPOINT cursorPoint; // GetCursorPosHookEntry
		W::LPSYSTEM_INFO sysInfo; // GetSystemInfoHookEntry
		W::PSYSTEM_POWER_CAPABILITIES powerCap; // GetPwrCapabilitiesHookEntry
		struct wmiQuery {
			W::VARIANT *varpt; // WMIQueryHookEntry
			W::LPCWSTR queryWMI; // WMIQueryHookEntry
		} _wmiQuery;
		// misc stuff
		ADDRINT getDiskFreeSpaceRetAddr;
	};

	// timing info
	//W::DWORD tick;
};


extern State::hookEntryArgsTLS _hookEntryTLSArgs;
//extern State::timeInfo _timeInfo;
extern State::globalState _globalState;

#define FetchHookTLS		State::hookEntryArgsTLS* in = &_hookEntryTLSArgs;
#define FetchTimeState		State::timeInfo* tinfo = &_globalState._timeInfo;
#define FetchGlobalState	State::globalState* gs = &_globalState;
