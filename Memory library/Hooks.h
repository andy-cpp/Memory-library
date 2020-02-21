#pragma once

#include <iostream>
#include <Windows.h>

namespace Hooks
{
	bool JMPHook(DWORD addr, DWORD size);
}