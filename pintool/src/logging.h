#pragma once
#include "pin.H"

#define LOGPATH "C:\\pin35\\"
#define LOGNAME "guards.log"
#define LOG_BUILD 1

#define LOG_AR(fmt, ...) \
	do { \
		if (!LOG_BUILD) break; \
		Logging::logMain(fmt"\n", __VA_ARGS__); \
	} while (0)


class Logging {

public:
	static FILE* mainLog;

	static VOID LOGGING_Init();
	static VOID LOGGING_Shutdown();
	static VOID logMain(const char * fmt, ...);

};