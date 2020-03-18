#pragma once
#include "syshooking.h"

namespace SYSHOOKS {
	// BluePill
	VOID NtDelayexecution_entry(syscall_t *sc, CONTEXT *ctx, SYSCALL_STANDARD std);
	VOID NtQueryDirectoryObject_exit(syscall_t *sc, CONTEXT *ctx, SYSCALL_STANDARD std);
	VOID NtOpenKey_exit(syscall_t * sc, CONTEXT * ctx, SYSCALL_STANDARD std);
	VOID NtCreateFile_entry(syscall_t *sc, CONTEXT *ctx, SYSCALL_STANDARD std);
	VOID NtEnumerateKey_exit(syscall_t *sc, CONTEXT *ctx, SYSCALL_STANDARD std);
	VOID NtQueryValueKey_exit(syscall_t *sc, CONTEXT *ctx, SYSCALL_STANDARD std);
	VOID NtQueryAttributesFile_entry(syscall_t *sc, CONTEXT *ctx, SYSCALL_STANDARD std);
	VOID NtQueryObject_exit(syscall_t *sc, CONTEXT *ctx, SYSCALL_STANDARD std);
	VOID NtUserEnumDisplayDevices_exit(syscall_t *sc, CONTEXT *ctx, SYSCALL_STANDARD std);
	VOID NtUserFindWindowEx_exit(syscall_t *sc, CONTEXT *ctx, SYSCALL_STANDARD std);
	VOID NtQuerySystemInformation_exit(syscall_t *sc, CONTEXT *ctx, SYSCALL_STANDARD std);
	VOID NtQueryInformationProcess_exit(syscall_t *sc, CONTEXT *ctx, SYSCALL_STANDARD std);
	VOID NtQueryPerformanceCounter_exit(syscall_t *sc, CONTEXT *ctx, SYSCALL_STANDARD std);

	// SoK DBI Anti-evasion
	VOID GenericScan_exit(syscall_t *sc, CONTEXT *ctx, SYSCALL_STANDARD std);
	VOID GenericHookDereference_exit(syscall_t *sc, CONTEXT *ctx, UINT32 argNum);
	VOID NtUnmapViewOfSection_entry(syscall_t *sc, CONTEXT *ctx, SYSCALL_STANDARD std);
	VOID NtProtectVirtualMemory_exit(syscall_t *sc, CONTEXT *ctx, SYSCALL_STANDARD std);
	VOID NtUnmapViewOfSection_exit(syscall_t *sc, CONTEXT *ctx, SYSCALL_STANDARD std);
	VOID NtFreeVirtualMemory_exit(syscall_t *sc, CONTEXT *ctx, SYSCALL_STANDARD std);
	VOID NtFreeUserPhysicalPages_exit(syscall_t *sc, CONTEXT *ctx, SYSCALL_STANDARD std);
	VOID NtQueryVirtualMemory_exit(syscall_t *sc, CONTEXT *ctx, SYSCALL_STANDARD std);
	VOID NtAllocateVirtualMemory_exit(syscall_t *sc, CONTEXT *ctx, SYSCALL_STANDARD std);
	VOID NtAllocateUserPhysicalPages_exit(syscall_t *sc, CONTEXT *ctx, SYSCALL_STANDARD std);
	VOID NtMapViewOfSection_exit(syscall_t *sc, CONTEXT *ctx, SYSCALL_STANDARD std);
	VOID NtGetMUIRegistryInfo_exit(syscall_t *sc, CONTEXT *ctx, SYSCALL_STANDARD std);
}