#pragma once
#include "pin.H"

#include "logging.h"

namespace W {
	#define WIN32_LEAN_AND_MEAN
	#include "windows.h"
	#include "Winternl.h"
	#include "Intsafe.h"
}

#include "winheaders.h"

#define OS_PAGE_SIZE			4096
#define OS_PAGE_OFFSET_BITS		12
#define OS_NUM_PAGES			(1 << (32 - OS_PAGE_OFFSET_BITS))
#define OS_CLEAR_MASK			0xFFFFF000

#define OS_ALLOCATION_SIZE		65536

#define OS_KUSER_SHARED_DATA_ADDRESS 0x7ffe0000
#define OS_KUSER_SHARED_DATA_SIZE 0x3e0 

#define MEMORY_VERBOSE		0
#define MEMORY_NX_PARANOID_OLD	0



typedef struct _MEMORY_BASIC_INFORMATION {
	W::PVOID  BaseAddress;
	W::PVOID  AllocationBase;
	W::ULONG  AllocationProtect;
	W::SIZE_T RegionSize;
	W::ULONG  State;
	W::ULONG  Protect;
	W::ULONG  Type;
} MEMORY_BASIC_INFORMATION, *PMEMORY_BASIC_INFORMATION;

typedef enum _MEMORY_INFORMATION_CLASS {
	MemoryBasicInformation
} MEMORY_INFORMATION_CLASS;

typedef unsigned char MEM_MASK;

typedef struct sez{
	ADDRINT start;
	ADDRINT end;
} struct_section;

// instrumentation initialization and callbacks
void MEMORY_Init();
void MEMORY_InstrumentINS(INS ins);
void MEMORY_LoadImage(IMG img);
void MEMORY_UnloadImage(IMG img);
void MEMORY_OnThreadStart(CONTEXT *ctxt);

// helper methods used also in hooks.cpp
void MEMORY_RegisterArea(ADDRINT start, ADDRINT size, MEM_MASK mask);
void MEMORY_ChangePermissionsForArea(ADDRINT start, ADDRINT size, MEM_MASK mask);
void MEMORY_UnregisterArea(ADDRINT start, size_t size);
void MEMORY_QueryWindows(ADDRINT address, ADDRINT *base, ADDRINT *size, MEM_MASK *mask);
MEM_MASK MEMORY_WinToPinCast(UINT32 permissions);
bool MEMORY_AddMappedMemoryStar(ADDRINT start, ADDRINT end, bool print);

// internal functions (TODO add prototypes for others? we will see...)
VOID MEMORY_AddPebAddress();
VOID MEMORY_AddProcessHeaps();
VOID MEMORY_AddKUserShareData();
bool MEMORY_AddMappedMemory(ADDRINT start, ADDRINT end, bool print, ADDRINT eip);
int MEMORY_AuxRegisterArea(ADDRINT start, ADDRINT size, MEM_MASK mask);
bool MEMORY_ChangePermissionsForAreaStar(ADDRINT start, ADDRINT size, MEM_MASK mask);
