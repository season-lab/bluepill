#pragma once
#include "pin.h"
#include "config.h"


/** THESE NUMBERS ARE TAILORED TO WINDOWS 7 SP1 **/
// we saw ordinals as high as 0x1a3 in ntdll
#define MAXSYSCALLS			0x200
// 0x1338 seen as max on https://j00ru.vexillium.org/syscalls/win32k/32/
#define MAXWIN32KSYSCALLS	0x1400

/* embedded ordinals for Win7 SP1 */
// we subtract 0x1000 for array indexing
#define NTUSERENUMDISPLAYDEVICES	(0x1185-0x1000)
#define NTUSERFINDWINDOWSEX			(0x118C-0x1000)
// GDI from SoK
#define NTGDIPOLYTEXTOUTW			(0x10fa-0x1000)
#define NTGDIDRAWSTREAM				(0x12db-0x1000)

// BluePill won't need more than that
#define SYSCALL_NUM_ARG 11

//syscall structure
typedef struct _syscall_t {
	ADDRINT syscall_number;
	union {
		ADDRINT args[12];
		struct {
			ADDRINT arg0, arg1, arg2, arg3;
			ADDRINT arg4, arg5, arg6, arg7;
			ADDRINT arg8, arg9, arg10, arg11;
		};
	};
} syscall_t;

// function signature of our hook functions
typedef void(*syscall_hook)(syscall_t *sc, CONTEXT *ctx, SYSCALL_STANDARD std);

typedef struct {
	syscall_t sc;
} pintool_tls;


namespace SYSHOOKING {
	VOID Init();
	VOID SetTLSKey(THREADID tid);
	VOID SyscallEntry(THREADID thread_id, CONTEXT *ctx, SYSCALL_STANDARD std, void *v);
	VOID SyscallExit(THREADID thread_id, CONTEXT *ctx, SYSCALL_STANDARD std, void *v);
	BOOL ReturnsToUserCode(CONTEXT* ctx);
}

