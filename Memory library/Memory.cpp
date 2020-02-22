#include "Memory.hpp"

bool Memory::CheckMemory(DWORD addr,uint32_t access, DWORD size)
{
	MEMORY_BASIC_INFORMATION mbi = { 0 };

	if (VirtualQuery((void*)addr, &mbi, sizeof(mbi)))
	{
		if (!(mbi.Protect & access))
			return false;

		if (!(mbi.State & MEM_COMMIT))
			return false;

		if (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS))
			return false;

		/* Get the start of the page */
		const auto start = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
		const auto end = static_cast<uintptr_t>(start + mbi.RegionSize);

		//check if our memory is within the readable region.
		return (addr >= start) && (((long)addr + size) <= end);
	}
	return false;
}

bool Memory::Readable(DWORD addr, DWORD size)
{
	return CheckMemory(addr, READABLE, size);
}

bool Memory::Writable(DWORD addr, DWORD size)
{
	return CheckMemory(addr, WRITABLE, size);
}

DWORD Memory::GetRelativeOffset(DWORD to, DWORD from, DWORD size)
{
	return (to - from) - size;
}

DWORD Memory::GetRealAddress(int32_t* relativeOffset)
{
	return (DWORD)((uintptr_t)relativeOffset - (TwosComplement(*(uint32_t*)relativeOffset)));
}

void* Memory::CopyFunction(void* ptr, int size)
{
	if (size < 5)
		return 0;

	uint8_t* pNewFunction = (uint8_t*)malloc(size + 5);
	if (pNewFunction == 0)
		return 0;
	//memset(pNewFunction, 0x90, size + 5);
	memcpy(pNewFunction, ptr, size);
	
	/* Set JMPBack to the original function. */
	pNewFunction[size + 0] = 0xE9;
	*(uintptr_t*)(pNewFunction + size + 1) = (uintptr_t)GetRelativeOffset((DWORD)ptr + size, (DWORD)pNewFunction + size);



	/* Set Execute permission, so we can execute the copied function */
	DWORD Old;
	VirtualProtect(pNewFunction, size + 5, PAGE_EXECUTE_READWRITE, &Old);

	return pNewFunction;
}
