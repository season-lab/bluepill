#pragma once
#include "pin.H"
#include "winheaders.h"

// CHAR (char)
#define GET_STR_TO_UPPER(c, buf, bufSize)	do { \
			size_t i; \
			for (i = 0; i < bufSize; i++) { \
				(buf)[i] = toupper((c)[i]); \
				if ((c)[i] == '\0') break; \
			} \
} while (0)

#define GET_STR(c, buf, bufSize)	do { \
			size_t i; \
			for (i = 0; i < bufSize; i++) { \
				(buf)[i] = (c)[i]; \
				if ((c)[i] == '\0') break; \
			} \
} while (0)

//T_CHAR (wchar_t)
#define GET_WSTR_TO_UPPER(c, buf, bufSize)	do { \
			size_t i; \
			for (i = 0; i < bufSize; i++) { \
				(buf)[i] = toupper((c)[2*i]); \
				if ((c)[2*i] == '\0') break; \
			} \
} while (0)

#define GET_WSTR(c, buf, bufSize)	do { \
			size_t i; \
			for (i = 0; i < bufSize; i++) { \
				(buf)[i] = (c)[2*i]; \
				if ((c)[2*i] == '\0') break; \
			} \
} while (0)

namespace Helper {

	size_t _strlen_a(const char *s);
	W::DWORD GetProcessIdByName(char* procName);
	string GetNameFromPid(W::DWORD pid);

};