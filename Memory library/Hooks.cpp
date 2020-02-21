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
