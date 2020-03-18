#include "syshooks.h"
#include "memory.h"

#include "state.h"
#include "HiddenElements.h"
#include "helper.h"

#define STR_QDO				"s"
#define WSTR_CREATEFILE		L"a"
#define WSTR_REGKEYORVAL	L"a"
#define WSTR_FILE			L"a"
#define STR_QSI				"a"

namespace SYSHOOKS {

	VOID NtDelayexecution_entry(syscall_t * sc, CONTEXT * ctx, SYSCALL_STANDARD std) {

		ACTIVE_HOOK(EN_NtDelayExecution);

		W::LARGE_INTEGER *li = (W::LARGE_INTEGER*)sc->arg1;
		W::UINT ll = (-li->QuadPart) / 10000LL;
		if (ll == 0 || ll > 1000000000)
			return;

		FetchTimeState;

		tinfo->sleepMs += ll;
		tinfo->sleepMsTick += ll;

		if (tinfo->lastMs == ll) {
			tinfo->numLastMs++;
		}
		else {
			tinfo->lastMs = ll;
			tinfo->numLastMs = 0;
		}

		// reset sleep value
		if (tinfo->numLastMs >= 5) {
			li->QuadPart = 0;
		}
		else {
			if (tinfo->sleepTime == 0)
				li->QuadPart = -BP_TIMER * 10000LL;
			else
				li->QuadPart = -tinfo->sleepTime * 10000LL;
		}

	}

	VOID NtQueryDirectoryObject_exit(syscall_t * sc, CONTEXT * ctx, SYSCALL_STANDARD std) {

		ACTIVE_HOOK(EN_NtQueryDirectoryObject);

		POBJECT_DIRECTORY_INFORMATION found = (POBJECT_DIRECTORY_INFORMATION)sc->arg1;

		if (found == NULL) return;

		char value[PATH_BUFSIZE];
		GET_STR_TO_UPPER(found->Name.Buffer, value, PATH_BUFSIZE);

		if (strstr(value, "VBOX") != NULL) { // TODO use HiddenElements
			LOG_AR("[NtQueryDO] - %s", value);
			size_t size = wcslen(found->Name.Buffer);
			for (size_t i = 0; i < size; i += 2) {
				PIN_SafeCopy(found->Name.Buffer, STR_QDO, sizeof(char));
			}
		}

	}

	VOID NtOpenKey_exit(syscall_t * sc, CONTEXT * ctx, SYSCALL_STANDARD std) {

		W::PHANDLE khandle = (W::PHANDLE)sc->arg0;
		if (khandle == nullptr) return;

		OBJECT_ATTRIBUTES *oa = (OBJECT_ATTRIBUTES*)sc->arg2;
		W::PWSTR path = oa->ObjectName->Buffer;

		if (PIN_GetContextReg(ctx, REG_GAX) != ERROR_SUCCESS || path == NULL || *path == NULL)
			return;

		char value[PATH_BUFSIZE];
		GET_STR_TO_UPPER(path, value, PATH_BUFSIZE);

		if (HiddenElements::shouldHideRegOpenKeyStr(value)) {
			LOG_AR("[NtOpenKey] - %s", value);
			// free right handle
			W::CloseHandle(*khandle);
			*khandle = (W::HANDLE) - 1;
			ADDRINT _eax = CODEFORINVALIDHANDLE; // return value to STATUS_INVALID_HANDLE
			PIN_SetContextReg(ctx, REG_GAX, _eax);
			return;
		}

	}

	/* TODO check if we still need it (look up past commits) 
	VOID NtOpenDirectoryObject_entry(syscall_t * sc, CONTEXT * ctx, SYSCALL_STANDARD std) {

		ACTIVE_HOOK(EN_NtOpenDirectoryObject);

		OBJECT_ATTRIBUTES *oa = (OBJECT_ATTRIBUTES*)sc->arg2;
		//if (oa->ObjectName->Buffer != NULL) {}
	}
	*/

	VOID NtCreateFile_entry(syscall_t * sc, CONTEXT * ctx, SYSCALL_STANDARD std) {

		ACTIVE_HOOK(EN_NtCreateFile);

		//if (PIN_GetContextReg(ctx, REG_GAX) != ERROR_SUCCESS) return; TODO serve?

		W::OBJECT_ATTRIBUTES *Obj = (W::OBJECT_ATTRIBUTES*)sc->arg2;
		W::ULONG mode = (W::ULONG)sc->arg7;
		W::PUNICODE_STRING p = Obj->ObjectName;

		char value[PATH_BUFSIZE];
		GET_STR_TO_UPPER(p->Buffer, value, PATH_BUFSIZE); // TODO print directly!

		if (HiddenElements::shouldHideGenericFileNameStr(value)) {
			LOG_AR("[NtCreateFile] - %s", value);
			for (W::USHORT i = p->Length - 8; i < p->Length - 1; i += 2) {
				// TODO make it configurable
				memcpy((char *)p->Buffer + i, WSTR_CREATEFILE, sizeof(wchar_t));
				PIN_SafeCopy((char *)p->Buffer + i, WSTR_CREATEFILE, sizeof(wchar_t));
			}
		}

	}

	VOID NtEnumerateKey_exit(syscall_t * sc, CONTEXT * ctx, SYSCALL_STANDARD std) {

		ACTIVE_HOOK(EN_NtEnumerateKey);

		KEY_INFORMATION_CLASS cl = (KEY_INFORMATION_CLASS)sc->arg2;
		if (cl == KeyBasicInformation) {
			PKEY_BASIC_INFORMATION str = (PKEY_BASIC_INFORMATION)sc->arg3;
			char value[PATH_BUFSIZE];
			GET_STR_TO_UPPER(str->Name, value, PATH_BUFSIZE);
			if (HiddenElements::shouldHideReqQueryValueStr(value)) {
				LOG_AR("[NtEnumerateKey] - %s", value);
				for (W::USHORT i = 0; i < str->NameLength - 1; i += 2) {
					// TODO make it configurable
					PIN_SafeCopy((char *)str->Name + i, WSTR_REGKEYORVAL, sizeof(wchar_t));
				}
			}
		}

	}

	VOID NtQueryValueKey_exit(syscall_t * sc, CONTEXT * ctx, SYSCALL_STANDARD std) {

		ACTIVE_HOOK(EN_NtQueryValueKey);

		if ((KEY_VALUE_INFORMATION_CLASS)sc->arg2 == KeyValuePartialInformation) {
			W::LPVOID str = (W::LPVOID)sc->arg3;
			W::PUNICODE_STRING query = (W::PUNICODE_STRING)sc->arg1;
			if (query->Buffer != NULL) {
				char value[PATH_BUFSIZE];
				GET_STR_TO_UPPER(query->Buffer, value, PATH_BUFSIZE);
				if (HiddenElements::shouldHideReqQueryValueStr(value)) {
					LOG_AR("[NtQueryValueKey] - %s", value);
					// TODO make it configurable
					for (W::USHORT i = 0; i < query->Length * 2 - 1; i += 2) {
						PIN_SafeCopy((char *)str + i, WSTR_REGKEYORVAL, sizeof(wchar_t));
					}
				}
			}
		}

	}

	VOID NtQueryAttributesFile_entry(syscall_t * sc, CONTEXT * ctx, SYSCALL_STANDARD std) {

		ACTIVE_HOOK(EN_NtQueryAttributesFile);

		W::OBJECT_ATTRIBUTES *Obj = (W::OBJECT_ATTRIBUTES*)sc->arg0;
		W::PUNICODE_STRING p = Obj->ObjectName;

		char value[PATH_BUFSIZE];
		GET_STR_TO_UPPER(p->Buffer, value, PATH_BUFSIZE); // TODO print directly!

		if (HiddenElements::shouldHideGenericFileNameStr(value)) {
			LOG_AR("[NtQueryAttributesFile] - %s", value);
			// TODO make it configurable
			for (W::USHORT i = p->Length - 8; i < p->Length - 1; i += 2) {
				//memcpy((char *)p->Buffer + i, WSTR_FILE, sizeof(wchar_t));
				PIN_SafeCopy((char *)p->Buffer + i, WSTR_FILE, sizeof(wchar_t));
			}
		}

	}

	VOID NtQueryObject_exit(syscall_t * sc, CONTEXT * ctx, SYSCALL_STANDARD std) {

		ACTIVE_HOOK(EN_NtQueryObject);

		if (sc->arg1 == 3) { // credits: Al-Khaser
			FetchGlobalState;
			gs->ntQueryCounter = (gs->ntQueryCounter + 1) % 2;

			if (gs->ntQueryCounter != 0)
				return;

			POBJECT_ALL_INFORMATION pObjectAllInfo = (POBJECT_ALL_INFORMATION)sc->arg2;
			W::ULONG NumObjects = pObjectAllInfo->NumberOfObjects;
			W::UCHAR *pObjInfoLocation = (W::UCHAR*)pObjectAllInfo->ObjectTypeInformation;

			for (UINT i = 0; i < NumObjects; i++) {

				POBJECT_TYPE_INFORMATION pObjectTypeInfo = (POBJECT_TYPE_INFORMATION)pObjInfoLocation;

				if (wcscmp(L"DebugObject", pObjectTypeInfo->TypeName.Buffer) == 0) {
					if (pObjectTypeInfo->TotalNumberOfObjects > 0) {
						LOG_AR("[NtQueryObject] - *");
						pObjectTypeInfo->TotalNumberOfObjects = 0;
					}
				}

				pObjInfoLocation = (unsigned char*)pObjectTypeInfo->TypeName.Buffer;

				pObjInfoLocation += pObjectTypeInfo->TypeName.MaximumLength;

				// TODO check this
				W::ULONG_PTR tmp = ((W::ULONG_PTR)pObjInfoLocation) & -(int)sizeof(void*);

				if ((W::ULONG_PTR)tmp != (W::ULONG_PTR)pObjInfoLocation)
					tmp += sizeof(void*);
				pObjInfoLocation = ((unsigned char*)tmp);
			}
		}

	}

	VOID NtUserEnumDisplayDevices_exit(syscall_t * sc, CONTEXT * ctx, SYSCALL_STANDARD std) {

		// TODO add ACTIVE_HOOK()

		LOG_AR("[NtUserFindWindowEx]");

		W::PDISPLAY_DEVICE disp = (W::PDISPLAY_DEVICE)sc->arg2;

		W::WCHAR* deviceID = (W::WCHAR*)((W::UINT32)disp + 0x148); //offset deviceID
		W::WCHAR* deviceString = (W::WCHAR*)((W::UINT32)disp + 0x44); //offset deviceString
		W::WCHAR* deviceName = (W::WCHAR*)disp->DeviceName; //offset deviceString

		if (wcsstr(deviceID, L"DEV_BEEF"))			memset(deviceID, 0, wcslen(deviceID));
		if (wcsstr(deviceString, L"VirtualBox"))	memset(deviceString, 0, wcslen(deviceString));
		if (wcsstr(deviceName, L"DISPLAY1"))		memset(disp->DeviceName, 0, wcslen(deviceName));

	}

	VOID NtUserFindWindowEx_exit(syscall_t * sc, CONTEXT * ctx, SYSCALL_STANDARD std) {

		ACTIVE_HOOK(EN_FindWindow);

		W::PUNICODE_STRING path1 = (W::PUNICODE_STRING)sc->arg2;
		W::PUNICODE_STRING path2 = (W::PUNICODE_STRING)sc->arg3;

		char value[PATH_BUFSIZE] = { 0 };

		if (path1 != NULL && path1->Buffer != NULL) {

			GET_STR_TO_UPPER(path1->Buffer, value, PATH_BUFSIZE);
			if (HiddenElements::shouldHideWindowStr(value)) {
				LOG_AR("[FindWindow] - %s", value);
				ADDRINT _eax = 0;
				PIN_SetContextReg(ctx, REG_GAX, _eax);
			}
		}
		if (path2 != NULL && path2->Buffer != NULL) {

			memset(value, 0, PATH_BUFSIZE);
			GET_STR_TO_UPPER(path2->Buffer, value, PATH_BUFSIZE);
			if (HiddenElements::shouldHideWindowStr(value)) {
				LOG_AR("[FindWindow] - %s", value);
				ADDRINT _eax = 0;
				PIN_SetContextReg(ctx, REG_GAX, _eax);
			}
		}

	}

	VOID NtQuerySystemInformation_exit(syscall_t * sc, CONTEXT * ctx, SYSCALL_STANDARD std) {

		ACTIVE_HOOK(SYSCALL_KEY_NtQuerySystemInformation);

		if (sc->arg0 == SystemProcessInformation) {

			LOG_AR("[NtQSI-proc] - SystemProcessInformation for process check");

			// cast to our structure to retrieve the information returned
			// from the NtSystemQueryInformation function
			PSYSTEM_PROCESS_INFO spi = (PSYSTEM_PROCESS_INFO)sc->arg1;
			if (spi == NULL) return; // avoid null pointer exception

			// iterate through all processes 
			while (spi->NextEntryOffset) {
				if (spi->ImageName.Buffer != nullptr) {
					char value[PATH_BUFSIZE];
					GET_STR_TO_UPPER(spi->ImageName.Buffer, value, PATH_BUFSIZE);
					if (HiddenElements::shouldHideProcessStr(value)) {
						PIN_SafeCopy(spi->ImageName.Buffer, BP_WFAKEPROCESS, sizeof(BP_WFAKEPROCESS));
						//wcscpy(spi->ImageName.Buffer, BP_WFAKEPROCESS);
					}
				}
				// calculate the address of the next entry.
				spi = (PSYSTEM_PROCESS_INFO)((W::LPBYTE)spi + spi->NextEntryOffset);
			}

		}

		else if (sc->arg0 == SystemFirmwareTableInformation) {

			PSYSTEM_FIRMWARE_TABLE_INFORMATION sfti = (PSYSTEM_FIRMWARE_TABLE_INFORMATION)sc->arg1;
			if (sfti->Action == SystemFirmwareTable_Get) {
				LOG_AR("[NtQSI-raw] - SystemFirmwareTableInformation for raw firmware query");

				ADDRINT sizeOut = *(W::ULONG*)sc->arg3;
				ADDRINT sizeIn = (W::ULONG)sc->arg2;
				if (sizeOut > sizeIn) return;

				// virtualbox part
				char vbox[] = { "VirtualBox" };
				char vbox2[] = { "vbox" };
				char vbox3[] = { "VBOX" };
				char escape[] = { "          " };
				char escape2[] = { "    " };
				W::ULONG sizeVbox = (W::ULONG)Helper::_strlen_a(vbox);
				W::ULONG sizeVbox2 = (W::ULONG)Helper::_strlen_a(vbox2);
				W::ULONG sizeVbox3 = (W::ULONG)Helper::_strlen_a(vbox3);


				PSYSTEM_FIRMWARE_TABLE_INFORMATION info = (PSYSTEM_FIRMWARE_TABLE_INFORMATION)sc->arg1;
				// scan entire bios in order to find vbox string
				for (size_t i = 0; i < info->TableBufferLength - sizeVbox; i++) {
					if (memcmp(info->TableBuffer + i, vbox, sizeVbox) == 0) {
						PIN_SafeCopy(info->TableBuffer + i, escape, sizeof(escape));
					}
					else if (memcmp(info->TableBuffer + i, vbox2, sizeVbox2) == 0 ||
						memcmp(info->TableBuffer + i, vbox3, sizeVbox3) == 0) {
						PIN_SafeCopy(info->TableBuffer + i, escape2, sizeof(escape2));
					}
				}

				// VMware part
				char vmware[] = { "VMware" };
				char escape3[] = { "      " };
				W::ULONG vmwareSize = (W::ULONG)Helper::_strlen_a(vmware);

				for (size_t i = 0; i < info->TableBufferLength - vmwareSize; i++) {
					if (memcmp(info->TableBuffer + i, vmware, vmwareSize) == 0) {
						PIN_SafeCopy(info->TableBuffer + i, escape3, sizeof(escape3));
					}
				}
			}

		}

		else if (sc->arg0 == SystemModuleInformation) {

			PRTL_PROCESS_MODULES pmi = (PRTL_PROCESS_MODULES)sc->arg1;
			if (pmi == NULL) return;

			if ((W::ULONG*)sc->arg3 == nullptr) return;

			ADDRINT sizeOut = *(W::ULONG*)sc->arg3;
			ADDRINT sizeIn = (W::ULONG)sc->arg2;
			if (sizeOut > sizeIn) return;

			LOG_AR("[NtQSI-drv] - SystemModuleInformation for system drivers");
			W::ULONG size = pmi->NumberOfModules;

			for (size_t i = 0; i < size; i++) {
				// TODO use HiddenElements?
				if (strstr((char*)pmi->Modules[i].FullPathName, "VBox") != NULL) {
					char* tmpAddr = (char*)pmi->Modules[i].FullPathName;
					size_t len = strlen(tmpAddr);
					for (size_t i = 0; i < len; i++) {
						PIN_SafeCopy(tmpAddr+i, STR_QSI, sizeof(char));
					}
					// demo for libdft
					//addTaintMemory((ADDRINT)tmpAddr, len, taintTag, true);
				}
			}
		}
	}

	VOID NtQueryInformationProcess_exit(syscall_t * sc, CONTEXT * ctx, SYSCALL_STANDARD std) {

		ACTIVE_HOOK(EN_NtQueryInformationProcess);

		W::PROCESSINFOCLASS ProcessInformationClass = (W::PROCESSINFOCLASS)sc->arg1;
		W::PVOID ProcessInformation = (W::PVOID)sc->arg2;
		W::ULONG ProcessInformationLength = (W::ULONG)sc->arg3;
		W::PULONG ReturnLength = (W::PULONG)sc->arg4;

		if (ProcessInformation != 0 && ProcessInformationLength != 0) {
			W::ULONG backupReturnLength = 0;
			if (ReturnLength != nullptr && (W::ULONG_PTR)ReturnLength >= (W::ULONG_PTR)ProcessInformation &&
				(W::ULONG_PTR)ReturnLength <= (W::ULONG_PTR)ProcessInformation + ProcessInformationLength)
			{
				backupReturnLength = *ReturnLength;
			}

			if (ProcessInformationClass == ProcessDebugFlags)
			{
				// gives Pin away as a debugger
				LOG_AR("[NtQIP-31] - ProcessDebugFlags");
				*((W::ULONG *)ProcessInformation) = PROCESS_DEBUG_INHERIT;
			}
			else if (ProcessInformationClass == ProcessDebugObjectHandle)
			{
				LOG_AR("[NtQIP-30] - ProcessDebugObjectHandle");
				if (_debugger) {
					*((W::HANDLE *)ProcessInformation) = (W::HANDLE)0;
					// set return value to STATUS_PORT_NOT_SET
					ADDRINT _eax = CODEFORSTATUSPORTNOTSET;
					PIN_SetContextReg(ctx, REG_GAX, _eax);
				}
			}
			else if (ProcessInformationClass == ProcessDebugPort)
			{
				LOG_AR("[NtQIP-7] - ProcessDebugPort");
				if (_debugger) {
					*((W::HANDLE *)ProcessInformation) = (W::HANDLE)0;
				}
			}
			else if (ProcessInformationClass == ProcessVmCounters)
			{
				//LOG_AR("[EVASION?] NtQueryInformation called with param -> 3");
				//TODO commented out as it is invoked frequently by legit APIs
				//TODO nothing to do here anyway, right?
			}
			else if (ProcessInformationClass == ProcessBasicInformation) //Fake parent
			{
				// TODO high false positives rate: add return site check?
				//LOG_AR("[NtQIP-0] - ProcessBasicInformation");
				((PPROCESS_BASIC_INFORMATION)ProcessInformation)->InheritedFromUniqueProcessId = (W::HANDLE)Helper::GetProcessIdByName("explorer.exe"); // TODO PID okay?
			}
			else if (ProcessInformationClass == ProcessBreakOnTermination)
			{
				// TODO double check with ScyllaHide (HookedFunctions.cpp)
				// but in our experiments it seemed fine
				//*((W::ULONG *)ProcessInformation) = ValueProcessBreakOnTermination;
				//LOG_AR("[NtQIP-29] - ProcessBreakOnTermination");
			}
			else if (ProcessInformationClass == ProcessHandleTracing)
			{
				// TODO double check here as well if we are good
				//LOG_AR("[NtQIP-32] - ProcessHandleTracing");
				//ntStat = IsProcessHandleTracingEnabled ? STATUS_SUCCESS : STATUS_INVALID_PARAMETER;
			}

			if (backupReturnLength != 0)
				*ReturnLength = backupReturnLength;
		}

	}

	VOID NtQueryPerformanceCounter_exit(syscall_t * sc, CONTEXT * ctx, SYSCALL_STANDARD std) {

		ACTIVE_HOOK(EN_NtQueryPerformanceCounter);

		W::LARGE_INTEGER *li = (W::LARGE_INTEGER*)sc->arg0;
		W::UINT32 ll = (-li->QuadPart) / 10000LL;

		if (ll == 0 || ll == INFINITE || ll > 3900000000)
			return;

		//LOG_AR("[NtQueryPerformanceCounter] - %u", ll);
		FetchTimeState;

		tinfo->sleepMs += ll;
		tinfo->sleepMsTick += ll;

		if (tinfo->lastMs2 == ll) {
			tinfo->numLastMs2++;
		}
		else {
			tinfo->lastMs2 = ll;
			tinfo->numLastMs2 = 0;
		}

		// reset sleep value
		if (tinfo->numLastMs2 >= 5) {
			li->QuadPart = 0;
		}
		else {
			li->QuadPart = -BP_TIMER * 10000LL;
		}

	}


	/***
	HOOKS FROM SOK DBI ANTI-EVASION
	***/

	VOID GenericScan_exit(syscall_t *sc, CONTEXT *ctx, SYSCALL_STANDARD std) {
		if (MEMORY_AddMappedMemoryStar(NULL, 0x7fff0000, true)) {
			//LOG_AR("ADDED MEMORY FROM SYSCALL %08x", sc->syscall_number);
		}
	}

	VOID GenericHookDereference_exit(syscall_t *sc, CONTEXT *ctx, UINT32 argNum) {
		W::PHANDLE pHandle = (W::PHANDLE)sc->arg0;

		ADDRINT _eax = PIN_GetContextReg(ctx, REG_GAX);
		if (_eax != 0 || pHandle != NULL) return;

		ADDRINT _startAddr, _size;
		MEM_MASK _mask;
		MEMORY_QueryWindows((ADDRINT)*pHandle, &_startAddr, &_size, &_mask);
		MEMORY_ChangePermissionsForArea(_startAddr, _size, _mask);
	}

	VOID NtProtectVirtualMemory_exit(syscall_t *sc, CONTEXT *ctx, SYSCALL_STANDARD std) {

		W::PVOID baseAddr = *(W::PVOID*)sc->arg1;
		// we were getting erratic results for size, probably needs to be saved on entry
		//W::PULONG size = (W::PULONG)sc->arg2; // on output gets rounded to page size
		//W::ULONG protect = (W::ULONG)sc->arg3;

		ADDRINT _eax = PIN_GetContextReg(ctx, REG_GAX);
		if (_eax != 0) return;

		ADDRINT _startAddr, _size;
		MEM_MASK _mask;
		MEMORY_QueryWindows((ADDRINT)baseAddr, &_startAddr, &_size, &_mask);
		MEMORY_ChangePermissionsForArea(_startAddr, _size, _mask);
	}

	VOID NtGetMUIRegistryInfo_exit(syscall_t *sc, CONTEXT *ctx, SYSCALL_STANDARD std) {
		W::PVOID data = (W::PVOID)sc->arg2;

		ADDRINT _eax = PIN_GetContextReg(ctx, REG_GAX);
		if (_eax != 0) return; // leap of faith

		ADDRINT _startAddr, _size;
		MEM_MASK _mask;
		MEMORY_QueryWindows((ADDRINT)data, &_startAddr, &_size, &_mask);
		MEMORY_RegisterArea(_startAddr, _size, _mask);
	}

	// TODO: move to TLS field; what about AllocationBase?
	W::SIZE_T storage_NtUnmapViewOfSection;
	VOID NtUnmapViewOfSection_entry(syscall_t *sc, CONTEXT *ctx, SYSCALL_STANDARD std) {
		W::PVOID baseAddr = (W::PVOID)sc->arg1;

		W::MEMORY_BASIC_INFORMATION memInfo;
		W::VirtualQuery(baseAddr, &memInfo, sizeof(memInfo));

		ASSERT(baseAddr == memInfo.AllocationBase, "Unaligned base for NtUnmapViewOfSection");

		// necessary for memory hook
		storage_NtUnmapViewOfSection = memInfo.RegionSize;
	}

	VOID NtUnmapViewOfSection_exit(syscall_t * sc, CONTEXT * ctx, SYSCALL_STANDARD std) {

		W::PVOID baseAddr = (W::PVOID)sc->arg1;

		ADDRINT _eax = PIN_GetContextReg(ctx, REG_GAX);
		if (_eax != 0) return;

		// memory hook
		MEMORY_UnregisterArea((ADDRINT)baseAddr, storage_NtUnmapViewOfSection);
	}

	VOID NtFreeVirtualMemory_exit(syscall_t * sc, CONTEXT * ctx, SYSCALL_STANDARD std) {

		W::PVOID *baseAddr = (W::PVOID*)sc->arg1;
		W::PSIZE_T size = (W::PSIZE_T)sc->arg2;
		W::ULONG type = (W::ULONG)sc->arg3;

		ADDRINT _eax = PIN_GetContextReg(ctx, REG_GAX);
		if (_eax != 0) return;

		// memory hook
		if (type == MEM_RELEASE) {
			MEMORY_UnregisterArea((ADDRINT)*baseAddr, *size);
		}

	}

	VOID NtFreeUserPhysicalPages_exit(syscall_t * sc, CONTEXT * ctx, SYSCALL_STANDARD std) {

		W::PULONG_PTR  userArray = (W::PULONG_PTR)sc->arg2;
		W::PULONG_PTR  numberOfPages = (W::PULONG_PTR)sc->arg1;

		ADDRINT _eax = PIN_GetContextReg(ctx, REG_GAX);
		if (_eax != 0) return;

		// TODO this one seems nasty

	}

	VOID NtQueryVirtualMemory_exit(syscall_t * sc, CONTEXT * ctx, SYSCALL_STANDARD std) {

		W::PVOID baseAddr = (W::PVOID)sc->arg1;
		MEMORY_BASIC_INFORMATION *mem = (MEMORY_BASIC_INFORMATION*)sc->arg3;

		ADDRINT _eax = PIN_GetContextReg(ctx, REG_GAX);
		if (_eax != 0) return;

		// TODO: use it to refresh our map?
		/*
		cout << "NtQueryVirtualMemory --->" <<
		"Allocation Base: 0x" << hex << mem->AllocationBase << endl <<
		"Base Address: 0x" << hex << mem->BaseAddress << endl <<
		"Size: 0x" << hex << mem->RegionSize << endl <<
		"Protect: 0x" << hex << mem->Protect << endl << endl;
		*/

	}

	VOID NtAllocateVirtualMemory_exit(syscall_t * sc, CONTEXT * ctx, SYSCALL_STANDARD std) {

		W::PVOID baseAddr = *(W::PVOID*)sc->arg1;
		W::PSIZE_T size = (W::PSIZE_T)sc->arg3;
		W::ULONG allocationType = (W::ULONG)sc->arg4;
		W::ULONG protect = (W::ULONG)sc->arg5;

		ADDRINT _eax = PIN_GetContextReg(ctx, REG_GAX);
		if (_eax != 0) return;

		// memory hook
		MEMORY_RegisterArea((ADDRINT)baseAddr, *size, MEMORY_WinToPinCast(protect));

		//cout << "BaseAddress: 0x" << hex << (UINT32)baseAddr << " " << hex << (UINT32)protect << endl;

		/*
		cout << "NtAllocateVirtualMemory -> " << endl
		<< "BaseAddress: 0x" << hex << (UINT32)*baseAddr << endl
		<< "EndAddress: 0x" << hex << (UINT32)*baseAddr + *size << endl
		<< "Size: " << *size << endl
		<< "Allocation Type: " << hex << allocationType << endl
		<< "Protection: " << hex << protect << endl << endl;
		*/
	}


	VOID NtAllocateUserPhysicalPages_exit(syscall_t * sc, CONTEXT * ctx, SYSCALL_STANDARD std) {

		W::PULONG_PTR  baseAddr = (W::PULONG_PTR)sc->arg1;
		W::PULONG_PTR  size = (W::PULONG_PTR)sc->arg2;

		ADDRINT _eax = PIN_GetContextReg(ctx, REG_GAX);
		if (_eax != 0) return;

		// TODO this one seems nasty

	}


	VOID NtMapViewOfSection_exit(syscall_t * sc, CONTEXT * ctx, SYSCALL_STANDARD std) {
#define STATUS_IMAGE_NOT_AT_BASE 0x40000003
		W::PVOID baseAddr = *(W::PVOID*)sc->arg2;
		W::PSIZE_T size = (W::PSIZE_T)sc->arg6;
		W::ULONG protect = (W::ULONG)sc->arg9;

		ADDRINT _eax = PIN_GetContextReg(ctx, REG_GAX);
		if (_eax != 0 && _eax != STATUS_IMAGE_NOT_AT_BASE) return;

		ADDRINT _startAddr, _size;
		MEM_MASK _mask;
		MEMORY_QueryWindows((ADDRINT)baseAddr, &_startAddr, &_size, &_mask);
		MEMORY_RegisterArea(_startAddr, _size, _mask); // TODO

		/*if (MEMORY_AddMappedMemoryStar(NULL, 0x7fff0000, true)) {
			cout << "ADDED MEMORY FROM SYSCALL " << sc->syscall_number << endl;
		}*/

	}

}
