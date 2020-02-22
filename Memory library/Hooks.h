#pragma once

#include <iostream>
#include <Windows.h>
#include "Memory.hpp"

namespace Hooks
{
	/* Standard Trampoline hook, jumps to hook */
	bool JMPHook(void* addr, void* hook, DWORD size = 5);

	/* VMT Hook Global, modifies the global vtable */
	bool VMTHookGlobal(void* object, int index, void* hook);
}