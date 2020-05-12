#include "Hooks.h"

bool Hooks::JMPHook(void* addr,void* hook, DWORD size, bool bPushRax)
{
	bool b32bit = (sizeof(void*) == 4) ? true : false;
	if (b32bit && size < 5)
		return false;
	if (!b32bit && size < 14)
		return false;
	/* Modify page protection */
	DWORD Old;
	if (!VirtualProtect((void*)addr, size, PAGE_EXECUTE_READWRITE, &Old))
		return false;

	/* Fill with nop's */
	memset((void*)addr, 0x90, size);

	BYTE* bData = (BYTE*)addr;
	/* Apply hook */
	if (b32bit) {
		*(uint8_t*)addr = 0xE9;
		*(uintptr_t*)((uintptr_t)addr + 1) = Memory::GetRelativeOffset<uintptr_t>((uintptr_t)hook, (uintptr_t)addr);
	}
	else
	{
		if (bPushRax)
			bData[0] = 0x50; // push rax
		else
			bData[0] = 0x90; // nop
		bData[1] = 0x48; bData[2] = 0xb8; // mov rax, hook
		memcpy(bData + 3, &hook, sizeof(hook));

		bData[3 + sizeof(void*)] = 0xff; // jmp rax
		bData[4 + sizeof(void*)] = 0xe0; // jmp rax
		bData[size - 1] = 0x58; // pop rax
	}
	/* Restore old page protection */
	if (!VirtualProtect((void*)addr, size, Old, &Old)) {
		/* We still return true even though protection wasn't restored due to having applied the hook. */
		return true;
	}

	return true;
}


Hooks::VMTHook::VMTHook(void* pclass, int index, void* hook)
{
	m_pclass = pclass;
	m_index = index;
	m_hook = hook;
}

bool Hooks::VMTHook::hook(void* pclass, int index, void* hook)
{
	if (pclass == 0)
		pclass = m_pclass;
	if (index == 0)
		index = m_index;
	if (hook == 0)
		hook = m_hook;

	return this->HookVMT(pclass, index, hook);
}

bool Hooks::VMTHook::HookVMT(void* pclass, int index, void* hook)
{
	if (pclass == 0)
		return false;
	if (hook == 0)
		return false;

	uintptr_t* vTable = *(uintptr_t**)pclass;
	/* Modify vTable protection */
	DWORD Old;
	if (!VirtualProtect((&vTable[index]), sizeof(void*), PAGE_EXECUTE_READWRITE, &Old))
		return false;

	vTable[index] = (uintptr_t)hook;

	/* Restore old protection */
	if (!VirtualProtect((&vTable[index]), sizeof(void*), Old, &Old))
		return false;

	return true;
}
