#pragma once

#include <iostream>
#include <Windows.h>
#include "Memory.hpp"

namespace Hooks
{
	bool JMPHook(void* addr, void* hook, DWORD size = 5);
}