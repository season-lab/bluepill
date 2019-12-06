#pragma once
#include "pin.h"

using namespace std; // TODO get rid of this...

// enable to avoid supplying command-line args to Pin (see below)
#define FIXED_KNOBS		1

// generic configuration parameters
#define BP_NUMCORES		4
#define BP_MAC_VENDOR	"\x07\x01\x33"
#define BP_NETVENDOR	"Intel"
#define BP_FAKEPROCESS	"cmd.exe"
#define BP_WFAKEPROCESS	L"abc.exe"
#define BP_TIMER		150
#define BP_ICMP_CREATE	300
#define BP_ICMP_ECHO	200
#define BP_HKL_LAYOUT	0x040c040c				/* France (we likely used it for Retefe) */
#define BP_MUTEX		"suppli"				/* used to create a valid handle */

// these are exposed for now through WMI queries only
#define BP_DISKSIZE		1000LL					/* HDD size in GB		*/
#define BP_ACPIDEV		L"ACPI\\ACPI0003\\0"	/* Name of false device */
#define BP_MACADDR		L"06:02:27:9C:BB:27"	/* consistency with BP_MAC_VENDOR? :) */
#define BP_MUI			"it-IT"					/* MUI language string	*/

// fake objects
#define BP_FAKEFILE		"C:\\a\\"
#define BP_FAKEFILE_W	L"C:\\a\\"
#define BP_POPEN		"cd"
#define BP_FAKEDLL		"sup.dll"
#define BP_FAKEDLL_W	L"sup.dll"
#define BP_FAKEDRV		"vga.sys"
#define BP_FAKEDRV_W	L"vga.sys"

// misc parameters used in the implementation
#define PATH_BUFSIZE	512

#if !FIXED_KNOBS
extern BOOL _nxKnob;
extern BOOL _paranoidKnob;
extern BOOL _rwKnob;
extern BOOL _leakKnob;
extern BOOL _libdftKnob;
extern BOOL _evasions;
extern BOOL _debugger;
#else
#define _paranoidKnob	false
#define _nxKnob			false
#define _rwKnob			false
#define _leakKnob		true
#define _libdftKnob		false
#define _evasions		true
#define _debugger		false
#endif
