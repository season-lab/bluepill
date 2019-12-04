#pragma once
#include "pin.H"

#include "helper.h"
#include "logging.h"

namespace W {
	#include <Windows.h>
	#include <wbemcli.h>
}

VOID WMI_Patch(W::LPCWSTR query, W::VARIANT *enumerator);