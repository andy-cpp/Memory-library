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

DWORD Memory::GetRealAddress(uint32_t* relativeOffset)
{
	return (DWORD)(relativeOffset - (TwosComplement(*relativeOffset) - 4));
}
