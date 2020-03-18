#include "state.h"

State::hookEntryArgsTLS _hookEntryTLSArgs;
//State::timeInfo _timeInfo;
State::globalState _globalState;

namespace State {
	void init() {
		// TODO check memset :-)
		memset(&_hookEntryTLSArgs, 0, sizeof(hookEntryArgsTLS));
		//memset(&_timeInfo, 0, sizeof(timeInfo));
		memset(&_globalState, 0, sizeof(globalState));

		// magic numbers
		_globalState._timeInfo.tick = 3478921;
		_globalState._timeInfo._edx_eax = 0x6000000002346573ULL;
	}

	globalState* getGlobalState() {
		return &_globalState;
	}

	hookEntryArgsTLS* getHookEntryTLSArgs() {
		return &_hookEntryTLSArgs;
	}

}