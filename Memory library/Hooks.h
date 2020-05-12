#pragma once

#include <iostream>
#include <Windows.h>
#include <map>

namespace Hooks
{
	/* Standard Trampoline hook, jumps to hook
		32bit hook size: 5 byte
		64bit hook size: 14 byte
		@param bPushRax (64 bit only) - decides whether you push rax before jumping to hook
	*/
	bool JMPHook(void* addr, void* hook, DWORD size = 5, bool bPushRax = false);

	class VMTHook
	{
	public:
		VMTHook() = default;
		~VMTHook() = default;

		VMTHook(void* pclass, int index, void* hook);

		bool hook(void* pclass = 0, int index = 0, void* hook = 0);

		static bool HookVMT(void* pclass, int index, void* hook);
	private:
		void* m_pclass = 0;
		int m_index = 0;
		void* m_hook = 0;
		void* m_originalfunc = 0;
	};
}

#include "Memory.hpp"