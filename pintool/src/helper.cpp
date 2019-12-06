#include "helper.h"
#include "winheaders.h"

#define MD5LEN  16

using namespace std;

namespace Helper {
	size_t Helper::_strlen_a(const char *s) {
		const char *s0 = s;

		if (s == 0) return 0;

		while (*s != 0) s++;

		return s - s0;
	}

	W::DWORD GetProcessIdByName(char* procName) {
		W::PROCESSENTRY32 entry;
		entry.dwSize = sizeof(W::PROCESSENTRY32);
		W::DWORD pid = NULL;

		W::HANDLE snapshot = W::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

		if (Process32First(snapshot, &entry) == TRUE) {
			while (Process32Next(snapshot, &entry) == TRUE) {
				if (strcmp(entry.szExeFile, procName) == 0) {
					W::HANDLE hProcess = W::OpenProcess(PROCESS_ALL_ACCESS, FALSE, entry.th32ProcessID);

					pid = W::GetProcessId(hProcess);

					W::CloseHandle(hProcess);
				}
			}
		}
		W::CloseHandle(snapshot);

		return pid;
	}

	string GetNameFromPid(W::DWORD pid) {

		W::PROCESSENTRY32 processInfo;
		processInfo.dwSize = sizeof(processInfo);
		W::HANDLE processesSnapshot = W::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
		if (processesSnapshot == (W::HANDLE) - 1) {
			return 0;
		}

		for (BOOL bok = Process32First(processesSnapshot, &processInfo); bok; bok = Process32Next(processesSnapshot, &processInfo)) {
			if (pid == processInfo.th32ProcessID) {
				W::CloseHandle(processesSnapshot);
				return processInfo.szExeFile;
			}

		}
		W::CloseHandle(processesSnapshot);
		return 0;

	}

}




