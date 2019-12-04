#include "wmi.h"
#include "config.h"

#include <iostream>
using namespace std;

#define SUCCEEDEDNEW(hr) (((W::HRESULT)(hr)) >= 0)

// false string use to patch away VBOXVIDEO
#define FALSESTR	"win32k"

// this may mean little to you, but means a lot to us developers (-:
#define PANICCIA	L"SASASASASASASASASA"	/*Sattoh				*/		

static W::HRESULT(WINAPI *pSafeArrayAccessData)(W::SAFEARRAY  *psa, void HUGEP **ppvData);
static W::HRESULT(WINAPI *pSafeArrayGetLBound)(W::SAFEARRAY *psa, UINT nDim, W::LONG *plLbound);
static W::HRESULT(WINAPI *pSafeArrayGetUBound)(W::SAFEARRAY *psa, UINT nDim, W::LONG *plUbound);
static W::HRESULT(WINAPI *pSafeArrayGetElement)(W::SAFEARRAY *psa, W::LONG *rgIndices, void *pv);

VOID WMI_Patch(W::LPCWSTR query, W::VARIANT *var) {

	// Get the data from the query
	if (var == NULL) return;

	if ((var)->n1.n2.vt != W::VT_NULL) {

		char value[PATH_BUFSIZE];
		GET_STR_TO_UPPER(query, value, PATH_BUFSIZE);

		LOG_AR("[WMI-Get]-%s", value);

		if (strstr(value, "NUMBEROFCORES") != NULL) {
			//set 8 cores in the machine
			var->n1.n2.n3.uintVal = BP_NUMCORES;
		}

		else if(strstr(value, "SIZE") != NULL) {
			//set new size of HDD
			var->n1.n2.n3.llVal = (BP_DISKSIZE * (1024LL * (1024LL * (1024LL))));
		}

		else if (strstr(value, "DEVICEID") != NULL) {
			//set the new device ID
			memset(var->n1.n2.n3.bstrVal, 0, wcslen(var->n1.n2.n3.bstrVal)*2);
			wcscpy(var->n1.n2.n3.bstrVal, BP_ACPIDEV);
		}

		else if (strstr(value, "MACADDRESS") != NULL) {
			//set new MAC Address
			memset(var->n1.n2.n3.bstrVal, 0, wcslen(var->n1.n2.n3.bstrVal) * 2);
			wcscpy(var->n1.n2.n3.bstrVal, BP_MACADDR);
		}

		else if (strstr(value, "MUILANGUAGES") != NULL) {
			//set new MAC Address
			//clean NTLog file
			W::HMODULE hmod = W::LoadLibraryA("OleAut32.dll");
			*(W::FARPROC *)&pSafeArrayAccessData = W::GetProcAddress(hmod, "SafeArrayAccessData");
			*(W::FARPROC *)&pSafeArrayGetLBound = W::GetProcAddress(hmod, "SafeArrayGetLBound");
			*(W::FARPROC *)&pSafeArrayGetUBound = W::GetProcAddress(hmod, "SafeArrayGetUBound");
			*(W::FARPROC *)&pSafeArrayGetElement = W::GetProcAddress(hmod, "SafeArrayGetElement");

			W::SAFEARRAY* saSources = var->n1.n2.n3.parray;
			W::LONG* pVals;
			W::HRESULT hr = pSafeArrayAccessData(saSources, (VOID**)&pVals); // direct access to SA memory

			if (SUCCEEDEDNEW(hr)) {
				W::LONG lowerBound, upperBound;
				pSafeArrayGetLBound(saSources, 1, &lowerBound);
				pSafeArrayGetUBound(saSources, 1, &upperBound);
				W::LONG iLength = upperBound - lowerBound + 1;

				// Iteare over our array of BTSR
				W::TCHAR* bstrItem;
				for (W::LONG ix = 0; ix < iLength; ix++) {
					pSafeArrayGetElement(saSources, &ix, (void *)&bstrItem);

					char value1[PATH_BUFSIZE];
					GET_WSTR_TO_UPPER(bstrItem, value1, PATH_BUFSIZE);

					if (strcmp(value1, "EN-US") == 0) {
						long* pData = (long*)saSources->pvData + ix;

						memset((char*)*pData, 0, strlen((char*)*pData));
						PIN_SafeCopy((char*)*pData, BP_MUI, strlen(BP_MUI));
					}
				}
			}
		}

		else if (strstr(value, "SOURCES") != NULL) {
			//clean NTLog file
			W::HMODULE hmod = W::LoadLibraryA("OleAut32.dll");
			*(W::FARPROC *)&pSafeArrayAccessData = W::GetProcAddress(hmod, "SafeArrayAccessData");
			*(W::FARPROC *)&pSafeArrayGetLBound = W::GetProcAddress(hmod, "SafeArrayGetLBound");
			*(W::FARPROC *)&pSafeArrayGetUBound = W::GetProcAddress(hmod, "SafeArrayGetUBound");
			*(W::FARPROC *)&pSafeArrayGetElement = W::GetProcAddress(hmod, "SafeArrayGetElement");

			W::SAFEARRAY* saSources = var->n1.n2.n3.parray;
			W::LONG* pVals;
			W::HRESULT hr = pSafeArrayAccessData(saSources, (VOID**)&pVals); // direct access to SA memory

			if (SUCCEEDEDNEW(hr)) {
				W::LONG lowerBound, upperBound;
				pSafeArrayGetLBound(saSources, 1, &lowerBound);
				pSafeArrayGetUBound(saSources, 1, &upperBound);
				W::LONG iLength = upperBound - lowerBound + 1;

				// iterate over our array of BTSR
				W::TCHAR* bstrItem;
				for (W::LONG ix = 0; ix < iLength; ix++) {
					pSafeArrayGetElement(saSources, &ix, (void *)&bstrItem);
					
					char value1[PATH_BUFSIZE];
					GET_WSTR_TO_UPPER(bstrItem, value1, PATH_BUFSIZE);

					if (strcmp(value1, "VBOXVIDEO") == 0) {
						long* pData = (long*)saSources->pvData + ix;

						memset((char*)*pData, 0, strlen((char*)*pData));
						PIN_SafeCopy((char*)*pData, FALSESTR, strlen(FALSESTR));
					}
				}
			}
		}
	}
}
