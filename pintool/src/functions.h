#pragma once
#include <map>
#include "pin.H"
#include "state.h"
#include "config.h"
#include "logging.h"
#include "wmi.h"

namespace W {
	#define WIN32_LEAN_AND_MEAN
	#include <Windows.h>
	#include <WinUser.h>
	#include <Ws2tcpip.h>
}

namespace Functions {
	void Init();
	void AddHooks(IMG img);
};

//typedef W::WCHAR PIN_OLECHAR; // for SysAllocString (no longer used)

/**********************
HOOKS FOR API FUNCTIONS
**********************/

// commented-out functions were replaced by lower-level hooks
//VOID RegOpenKeyExHook(W::LPCTSTR * path);
//VOID GetFileAttributesHook(W::LPCSTR * path);
VOID GetAdaptersInfoHookEntry(PIP_ADAPTER_INFO *adapInfo, W::PULONG *size);
VOID GetAdaptersInfoHookExit(ADDRINT ret);
//VOID CreateFileHook();
VOID FindWindowHook(W::LPCTSTR* path1, W::LPCTSTR* path2);
VOID WNetGetProviderNameHookEntry(W::LPTSTR* buffer);
VOID WNetGetProviderNameHookExit();
VOID GetTickCountHook(W::DWORD* ret);
VOID SetTimerHook(W::UINT *time);
VOID WaitForSingleObjectHook(W::DWORD *time);
VOID IcmpCreateFileEntryHook();
VOID IcmpCreateFileExitHook();
VOID IcmpSendEchoHook(W::DWORD *time);
//VOID SysAllocStringHook(const PIN_OLECHAR **path, ADDRINT ip);
VOID GetDiskFreeSpaceHookExit();
VOID FindFirstFileHook(W::LPCTSTR *path);
//VOID GetSystemTimeAsFileTimeHook(W::LPFILETIME *lpSystemTimeAsFileTime);
VOID _popenHook(const char **command);
VOID LoadLibraryAHook(const char **lib);
VOID LoadLibraryWHook(const wchar_t **lib);
VOID GetDeviceDriverBaseNameHookEntry(W::LPTSTR *lpBaseName);
VOID GetDeviceDriverBaseNameHookExit();
VOID GetWindowTextHookEntry(W::LPTSTR *lpString);
VOID GetWindowTextHookExit();
VOID GetModuleFileNameHookEntry(W::LPTSTR *name);
VOID GetModuleFileNameHookExit();
//VOID LdrGetDllHandleHook(W::PUNICODE_STRING *p);
VOID SetupDiGetDeviceRegistryPropertyHookExit(ADDRINT ret);
VOID SetupDiGetDeviceRegistryPropertyHookEntry(W::PBYTE *buffer);
VOID CloseHandleHookEntry(W::HANDLE *handle);
VOID CloseHandleHookExit(W::BOOL *ret);
VOID GetCursorPosHookEntry(ADDRINT retAddr, W::LPPOINT *point);
VOID GetCursorPosHookExit();
VOID GetKeyboardLayoutHookExit(W::HKL* ret);
VOID GetSystemInfoHookEntry(W::LPSYSTEM_INFO *lpSystemInfo);
VOID GetSystemInfoHookExit();
VOID GetPwrCapabilitiesHookEntry(W::PSYSTEM_POWER_CAPABILITIES *lpspc);
VOID GetPwrCapabilitiesHookExit();
VOID WMIQueryHookEntry(W::LPCWSTR *query, W::VARIANT **var);
VOID WMIQueryHookExit();
VOID WMIExecQueryHook(W::TCHAR **Query);
VOID ChangeServiceConfigWHook(W::SC_HANDLE *hService);
VOID GetEnvHookEntry(CHAR** var);
BOOL InitiateSystemShutdownExWHook(
	W::LPSTR lpMachineName,
	W::LPSTR lpMessage,
	W::DWORD dwTimeout,
	W::BOOL  bForceAppsClosed,
	W::BOOL  bRebootAfterShutdown,
	W::DWORD dwReason);
//VOID SCardDisconnectHookEntry(W::DWORD *par); // Ramillo out
VOID GetDiskFreeSpaceHookEntry(ADDRINT retAddr,
		W::PULARGE_INTEGER *lpFreeBytesAvailable,
		W::PULARGE_INTEGER *lpTotalNumberOfBytes,
		W::PULARGE_INTEGER *lpTotalNumberOfFreeBytes);

/*DEBUG HOOK*/
VOID CompareStringHook(W::LPCTSTR *s1, W::LPCTSTR *s2);
VOID RtlCompareUnicodeStringHook(W::PCUNICODE_STRING *s1, W::PCUNICODE_STRING *s2);
VOID wcsstrHook(wchar_t** wcs1, const wchar_t** wcs2);
VOID wcscmpHook(wchar_t** wcs1, const wchar_t** wcs2);
VOID strcmpHook(char** wcs1, const char** wcs2);
VOID strstrHook(char** wcs1, const char** wcs2);

/*Logging hooks*/
VOID timeLogHook(ADDRINT retAddr, const char* funName);
VOID logGetSystemTimeAsFileTime(ADDRINT retAddr);


// some of the following values might be unused as we
// remove hooks that are no longer necessary
enum {
	SLEEP_INDEX = 0,
	REGQUERYVALUE_INDEX,
	REGOPENKEY_INDEX,
	GETFILEATTRIBUTES_INDEX,
	GETADAPTER_INDEX,
	CREATEFILE_INDEX,
	FINDWINDOW_INDEX,
	WGETNET_INDEX,
	//NEXTPROC_INDEX,
	EXECQUERY_INDEX,
	GETTICKCOUNT_INDEX,
	SETTIMER_INDEX,
	WAITOBJ_INDEX,
	ICMPFILE_INDEX,
	ICMPECHO_INDEX,
	ZWQUERY_INDEX,
	SYSALLOC_INDEX,
	WMI_INDEX,
	GETDISKSPACE_INDEX,
	EXECQ_INDEX,
	GETFIRSTFILE_INDEX,
	TIMEASFILE_INDEX,
	POPEN_INDEX,
	LOADLIBA_INDEX,
	LOADLIBW_INDEX,
	VPROTECT_INDEX,
	DEVICEBASE_INDEX,
	WINNAME_INDEX,
	GETMODULE_INDEX,
	GETMODULEX_INDEX,
	LDRHND_INDEX,
	SETUPDEV_INDEX,
	CLOSEH_INDEX,
	GETCUR_INDEX,
	GETENV_INDEX,
	KEYB_INDEX,
	SYSINFO_INDEX,
	POWCAP_INDEX,
	CHANGSERV_INDEX,
	SHUTD_INDEX,
	//SANDBOX LOG
	GETPROC_INDEX,
	GETMODA_INDEX,
	GETMODW_INDEX,
	CONNECT_INDEX,
	//SCARD_INDEX,
	/********* index for registry report ***********/
	REGOPEN_INDEX = 60,
	REGSET_INDEX,
	REGCLOSE_INDEX,
	REGCREATE_INDEX,
	/********* index for special logging hooks ***********/
	NTDELAYEXEC_INDEX = 70,
	NTQUERYPERF_INDEX,
	/*************  index for debug **************/
	CMPSTR_INDEX = 100,
	RTLSTR_INDEX,
	WCSSTR_INDEX,
	WCSCMP_INDEX,
	STRSTR_INDEX,
	STRCMP_INDEX
};

#define MAX_HOOK_FUNCTIONS_INDEX	128 // TODO handle the enum above more nicely