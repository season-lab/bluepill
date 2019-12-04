#pragma once
#include <cstddef>

/**
Check HiddenElements.cpp for processes, files, registry
key or values, and other artifacts you want to hide.
**/

namespace HiddenElements {
	#define MAX_NUMHOOKS		100
	#define MAX_HOOKS_IN_GROUP	64
	extern bool KTM[MAX_NUMHOOKS];

	void initializeHiddenStuff();

	// check element against list of artifacts
	bool shouldHideProcessStr(const char* procNameUpper);
	bool shouldHideRegOpenKeyStr(const char* strUpper);
	bool shouldHideReqQueryValueStr(const char* strUpper);
	bool shouldHideGenericFileNameStr(const char* strUpper);
	bool shouldHideWindowStr(const char* strUpper);
	bool shouldWMIQueryFail(const char* strUpper);

	extern char* hiddenProcesses[MAX_HOOKS_IN_GROUP];
	extern char* regOpenKeyStrings[MAX_HOOKS_IN_GROUP];
	extern char* regQueryValueStrings[MAX_HOOKS_IN_GROUP];
	extern char* genericFilenames[MAX_HOOKS_IN_GROUP];
	extern char* windowNames[MAX_HOOKS_IN_GROUP];
	extern char* WMIQueryFail[MAX_HOOKS_IN_GROUP];

	/**
	We prototyped a GUI for internal use that can selectively
	disable hooks while the tool runs.For this reason several
	hooks come with a ACTIVE_HOOK() operation in the prologue.
	The GUI component would then alter the contents of the KTM
	array to turn off or reactivate hooks.For the initial
	public release of BluePill we have removed the GUI as its
	development didn't keep up the pace with the new additions
	to the tool, but we may add it at a later point.We thus
	we leave some code as it is, both to favor a reintegration
	and to let users manipulate KTM directly if they wish to.
	**/

	// those were manipulated by the GUI
	void updateHiddenProcesses(char** procNames);
	void updateRegOpenKeyStrings(char** strings);
	void updateRegQueryValueStrings(char** strings);
	void updateGenericFileNames(char** fileNames);
	void updateWindowNames(char** windowsNames);
	void updateWMIQueryFail(char** strings);
	void setGroup(int groupID, bool value);

	#define ACTIVATE_ALL		0	// use 0 if you alter KTM	
	#if ACTIVATE_ALL
	#define ACTIVE_HOOK(index) \
		do { } while(0)
	#else
	#define ACTIVE_HOOK(index) \
		do { if(!HiddenElements::KTM[index]) return; } while(0)
	#endif
};

/**
Those are out of sync with actual hooks available in BluePill.
We should improve the design to have a single enum value to
handle both the hook ID and the toggle for it defined here.
**/

typedef enum _HOOK_LIST_ENABLE_DISABLE {
	/** syscall category **/
	EN_NtQueryInformationProcess,
	EN_NtQuerySystemInformation,
	EN_NtQueryPerformanceCounter,
	EN_NtOpenProcess,
	EN_NtRequestWaitReplyPort,
	EN_NtAllocateVirtualMemory,
	EN_NtProtectVirtualMemory,
	EN_NtCreateFile,
	EN_NtWriteVirtualMemory,
	EN_NtMapViewOfSection,
	EN_NtCreateThreadEx,
	EN_NtQueueApcThread,
	EN_NtResumeThread,
	EN_NtDelayExecution,
	EN_NtQueryDirectoryObject,
	EN_NtOpenKey,
	EN_NtOpenKeyEx,
	EN_NtEnumerateKey,
	EN_NtQueryValueKey,
	EN_NtQueryAttributesFile,
	EN_NtOpenDirectoryObject,
	EN_NtQueryObject,
	EN_NtClose,
	/** function category **/
	EN_PlaceholderForMem, // MEMORY group
	EN_GetFileAttributes, // FILE group
	EN_FindFirstFile,
	EN_FindNextFile,
	EN_CreateFile,
	EN_IsDebuggerPresent, // DEBUGGER group
	EN_GetCursorPos, // GUI group
	EN_FindWindow,
	EN_GetWindowText,
	EN_SysAllocString, // WMI group
	EN_GetDiskFreeSpaceEx, // HARDWARE group
	EN_GetPwrCapabilities,
	EN_SetupDiGetDeviceRegistryProperty,
	EN_EnumDisplaySettings,
	EN_K32GetDeviceDriverBaseName,
	EN_GetModuleFileName, // PROCESS group
	EN_GetModuleFileNameEx,
	EN_Process32Next,
	EN_CreateProcessInternal,
	EN__popen, // PIPE group
	EN__wpopen,
	EN__tpopen,
	EN_LoadLibrary, // DLL group
	EN_LoadLibraryEx,
	EN_LdrGetDllHandle,
	EN_LdrGetDllHandleEx,
	EN_GetTickCount, // TIME group
	EN_SetTimer,
	EN_GetSystemTimeAsFileTime,
	EN_WaitForSingleObject, // MUTEX group
	EN_IcmpCreateFile, // NETWORK group
	EN_IcmpSendEcho,
	EN_WNetGetProviderName,
	EN_GetAdaptersInfo,
	EN_RegOpenKeyEx, // REGISTRY group
	EN_RegOpenKey,
	EN_RegQueryValueEx,
	EN_RtlCompareUnicodeString, // STRING group
	EN_RtlEqualUnicodeString,
	EN_wcsstr,
	EN_wcscmp,
	EN_wcsncmp,
	EN__wcsnicmp,
	EN_strstr,
	EN_strcmp,
	EN__strcmpi,
	EN_CompareString,
	EN_CompareStringEx,
	EN_GetSystemInformation,
	EN_GetKeyboardLayout,
	/** instruction category **/
	EN_rdtsc,
	EN_cpuid,
	EN_int0x2d,
	EN_in,
	/** log **/
	EN_GetProcAddr,
	EN_GetModHand

} HOOK_LIST;

typedef enum {
	EN_GR_L_MEMORY,
	EN_GR_L_FILE,
	EN_GR_L_DEBUGGER,
	EN_GR_L_GUI,
	EN_GR_L_WMI,
	EN_GR_L_HARDWARE,
	EN_GR_L_PROCESS,
	EN_GR_L_PIPE,
	EN_GR_L_DLL,
	EN_GR_L_TIME,
	EN_GR_L_MUTEX,
	EN_GR_L_NETWORK,
	EN_GR_L_REGISTRY,
	EN_GR_L_STRING,
	EN_GR_S_ALL,
	EN_GR_I_ALL
} HOOK_GROUPS;

