#include "HiddenElements.h"
#include "pin.H"
#include <iostream>

namespace HiddenElements {

	bool KTM[MAX_NUMHOOKS];

	char* hiddenProcesses[MAX_HOOKS_IN_GROUP];
	char* regOpenKeyStrings[MAX_HOOKS_IN_GROUP];
	char* regQueryValueStrings[MAX_HOOKS_IN_GROUP];
	char* genericFilenames[MAX_HOOKS_IN_GROUP];
	char* windowNames[MAX_HOOKS_IN_GROUP];
	char* WMIQueryFail[MAX_HOOKS_IN_GROUP];

	char* defaultHiddenProcesses[] = {
		"VBOX", "ORACLE", "OLLYDBG", "PROCESSHACKER",
		"AUTORUNS", "PYTHON", "REGSHOT", "TCPVIEW",
		"FILEMON", "PROCMON", "REGMON", "PROCEXP",
		"IDAQ", "IMMUNITY", "WIRESHARK", "DUMPCAP",
		"HOOKEXPLORER", "IMPORTREC", "PETOOLS", "LORDPE",
		"SYSINSPECTOR", "ANALYZER", "SNIFF", "WINDBG",
		"JOEBOX", "VMWARE", "VMUSRVC", "VMTOOLSD", "DF5SERV",
		"PIN", "CMD",
		NULL
	};

	char* defaultRegOpenKeyStrings[] = {
		"VIRTUALBOX", "VBOX", "GUEST ADDITION", "ORACLE",
		"PCI", "VIRTUAL", "DEVICE", "DRIVER", "CYGWIN", // "FLAG",
		"ENUM\\IDE", "VMWARE", "DESCRIPTION\\SYSTEM",
		"CONTROL\\VIDEO",
		NULL
	};

	char* defaultRegQueryValueStrings[] = {
		"VIRTUALBOX", "VBOX", "IDA", "ORACLE", "06/23/99",
		"VMWARE", "BIOS", "VIRTUAL_DISK",
		NULL
	};

	char* defaultGenericFilenames[] = {
		"VIRTUALBOX", "VBOX", "ORACLE", "GUEST", "PHYSICALDRIVE",
		"VMMOUSE", "HGFS", "VMHGFS", "VMCI", "VMWARE",
		NULL
	};

	char* defaultWindowNames[] = {
		"VIRTUALBOX", "VBOX", "ORACLE",
		"QWINDOWICON", "OLLY", "ID", "GUEST",
		NULL
	};

	char* defaultWMIQueryFail[] = {
		"PNPENTITY", "NTEVENTLOGFILE", "LOGICALDISK",
		"BIOS", "NETWORKADAPTER", "PROCESSOR",
		"OPERATINGSYSTEM", "COMPUTERSYSTEM",
		NULL
	};

	static inline int copyArrayOfStringRefs(char** src, char** dest) {
		char** tmp = dest;
		while (*src) {
			*tmp = *src;
			tmp++, src++;
		}
		*tmp = NULL;
		return tmp - dest; // number of copied elements
	}

	void initializeHiddenStuff() {
		updateHiddenProcesses(NULL);
		updateRegOpenKeyStrings(NULL);
		updateRegQueryValueStrings(NULL);
		updateGenericFileNames(NULL);
		updateWindowNames(NULL);
		updateWMIQueryFail(NULL);
		int i;
		for (i = 0; i < MAX_NUMHOOKS; i++) {
			KTM[i] = TRUE;
		}
	}

	static inline void setGroupAux(const int* IDs, int numIDs, bool value) {
		for (int i = 0; i < numIDs; i++)
			KTM[IDs[i]] = value;
	}

	void setGroup(int groupID, bool value) {

		static const int libMemory[] = {
			EN_PlaceholderForMem // MEMORY group
		};

		static const int libFile[] = {
			EN_GetFileAttributes, // FILE group
			EN_FindFirstFile,
			EN_FindNextFile,
			EN_CreateFile
		};

		static const int libDebugger[] = {
			EN_IsDebuggerPresent // DEBUGGER lonely group
		};

		static const int libGUI[] = {
			EN_GetCursorPos, // GUI group
			EN_FindWindow,
			EN_GetWindowText,
			EN_SysAllocString
		};

		static const int libWMI[] = {
			EN_SysAllocString // WMI lonely group
		};

		static const int libHardware[] = {
			EN_GetDiskFreeSpaceEx, // HARDWARE group
			EN_SetupDiGetDeviceRegistryProperty,
			EN_EnumDisplaySettings,
			EN_K32GetDeviceDriverBaseName
		};

		static const int libProcess[] = {
			EN_GetModuleFileName, // PROCESS group
			EN_GetModuleFileNameEx,
			EN_Process32Next,
			EN_CreateProcessInternal
		};

		static const int libPipe[] = {
			EN__popen, // PIPE group
			EN__wpopen,
			EN__tpopen
		};

		static const int libDLL[] = {
			EN_LoadLibrary, // DLL group
			EN_LoadLibraryEx,
			EN_LdrGetDllHandle,
			EN_LdrGetDllHandleEx
		};

		static const int libTime[] = {
			EN_GetTickCount, // TIME group
			EN_SetTimer,
			EN_GetSystemTimeAsFileTime
		};

		static const int libMutex[] = {
			EN_WaitForSingleObject // MUTEX lonely group
		};

		static const int libNetwork[] = {
			EN_IcmpCreateFile, // NETWORK group
			EN_IcmpSendEcho,
			EN_WNetGetProviderName,
			EN_GetAdaptersInfo
		};

		static const int libRegistry[] = {
			EN_RegOpenKeyEx, // REGISTRY group
			EN_RegOpenKey,
			EN_RegQueryValueEx,
			EN_RtlCompareUnicodeString
		};

		static const int libString[] = {
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
			EN_CompareStringEx
		};

		static const int syscallsAll[] = {
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
			EN_NtClose
		};

		static const int instructionsAll[] = {
			EN_rdtsc,
			EN_cpuid,
			EN_int0x2d
		};

		switch (groupID) {
		case EN_GR_L_MEMORY:
			setGroupAux(libMemory, sizeof(libMemory) / sizeof(libMemory[0]), value);
			break;
		case EN_GR_L_FILE:
			setGroupAux(libFile, sizeof(libFile) / sizeof(libFile[0]), value);
			break;
		case EN_GR_L_DEBUGGER:
			setGroupAux(libDebugger, sizeof(libDebugger) / sizeof(libDebugger[0]), value);
			break;
		case EN_GR_L_GUI:
			setGroupAux(libGUI, sizeof(libGUI) / sizeof(libGUI[0]), value);
			break;
		case EN_GR_L_WMI:
			setGroupAux(libWMI, sizeof(libWMI) / sizeof(libWMI[0]), value);
			break;
		case EN_GR_L_HARDWARE:
			setGroupAux(libHardware, sizeof(libHardware) / sizeof(libHardware[0]), value);
			break;
		case EN_GR_L_PROCESS:
			setGroupAux(libProcess, sizeof(libProcess) / sizeof(libProcess[0]), value);
			break;
		case EN_GR_L_PIPE:
			setGroupAux(libPipe, sizeof(libPipe) / sizeof(libPipe[0]), value);
			break;
		case EN_GR_L_DLL:
			setGroupAux(libDLL, sizeof(libDLL) / sizeof(libDLL[0]), value);
			break;
		case EN_GR_L_TIME:
			setGroupAux(libTime, sizeof(libTime) / sizeof(libTime[0]), value);
			break;
		case EN_GR_L_MUTEX:
			setGroupAux(libMutex, sizeof(libMutex) / sizeof(libMutex[0]), value);
			break;
		case EN_GR_L_NETWORK:
			setGroupAux(libNetwork, sizeof(libNetwork) / sizeof(libNetwork[0]), value);
			break;
		case EN_GR_L_REGISTRY:
			setGroupAux(libRegistry, sizeof(libRegistry) / sizeof(libRegistry[0]), value);
			break;
		case EN_GR_L_STRING:
			setGroupAux(libString, sizeof(libString) / sizeof(libString[0]), value);
			break;
		case EN_GR_S_ALL:
			setGroupAux(syscallsAll, sizeof(syscallsAll) / sizeof(syscallsAll[0]), value);
			break;
		case EN_GR_I_ALL:
			setGroupAux(instructionsAll, sizeof(instructionsAll) / sizeof(instructionsAll[0]), value);
			break;
		default:
			std::cerr << "UNKNOWN GROUP ID! TRY AND CHECK KTM INSTEAD" << std::endl;
		}
	}


	void updateHiddenProcesses(char** procNames) {
		if (!procNames)
			copyArrayOfStringRefs(defaultHiddenProcesses, hiddenProcesses);
		else
			copyArrayOfStringRefs(procNames, hiddenProcesses);
	}

	void updateRegOpenKeyStrings(char** strings) {
		if (!strings)
			copyArrayOfStringRefs(defaultRegOpenKeyStrings, regOpenKeyStrings);
		else
			copyArrayOfStringRefs(strings, regOpenKeyStrings);
	}

	void updateRegQueryValueStrings(char** strings) {
		if (!strings)
			copyArrayOfStringRefs(defaultRegQueryValueStrings, regQueryValueStrings);
		else
			copyArrayOfStringRefs(strings, regQueryValueStrings);
	}

	void updateGenericFileNames(char** fileNames) {
		if (!fileNames)
			copyArrayOfStringRefs(defaultGenericFilenames, genericFilenames);
		else
			copyArrayOfStringRefs(fileNames, genericFilenames);
	}

	void updateWindowNames(char** windowsNames) {
		if (!windowsNames)
			copyArrayOfStringRefs(defaultWindowNames, windowNames);
		else
			copyArrayOfStringRefs(windowsNames, windowNames);
	}

	void updateWMIQueryFail(char** strings) {
		if (!strings)
			copyArrayOfStringRefs(defaultWMIQueryFail, WMIQueryFail);
		else
			copyArrayOfStringRefs(strings, WMIQueryFail);
	}

	static inline bool lookupSubstring(const char* str, char** strings) {
		while (*strings) {
			if (strstr(str, *strings)) return true;
			strings++;
		}
		return false;
	}

	bool shouldHideProcessStr(const char* procNameUpper) {
		return lookupSubstring(procNameUpper, hiddenProcesses);
	}

	bool shouldHideRegOpenKeyStr(const char* strUpper) {
		return lookupSubstring(strUpper, regOpenKeyStrings);
	}

	bool shouldHideReqQueryValueStr(const char* strUpper) {
		return lookupSubstring(strUpper, regQueryValueStrings);
	}

	bool shouldHideGenericFileNameStr(const char * strUpper) {
		return lookupSubstring(strUpper, genericFilenames);
	}

	bool shouldHideWindowStr(const char* strUpper) {
		return lookupSubstring(strUpper, windowNames);
	}

	bool shouldWMIQueryFail(const char * strUpper) {
		return lookupSubstring(strUpper, WMIQueryFail);
	}

} /* END OF NAMESPACE*/
