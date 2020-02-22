#include "Hooks.h"

bool Hooks::JMPHook(void* addr,void* hook, DWORD size)
{
	/* Modify page protection */
	DWORD Old;
	VirtualProtect((void*)addr, size, PAGE_EXECUTE_READWRITE, &Old);

	/* Fill with nop's */
	memset((void*)addr, 0x90, size);

	/* Apply hook */
	*(uint8_t*)addr = 0xE9;
	*(uintptr_t*)((uintptr_t)addr + 1) = Memory::GetRelativeOffset((DWORD)hook, (DWORD)addr);

	/* Restore old page protection */
	VirtualProtect((void*)addr, size, Old, &Old);

	return true;
}

bool Hooks::VMTHookGlobal(void* object, int index, void* hook)
{
	uintptr_t* vTable = *(uintptr_t**)object;


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
