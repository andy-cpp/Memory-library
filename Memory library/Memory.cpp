#include "Memory.hpp"

bool Memory::CheckMemory(uintptr_t addr,uint32_t access, DWORD size)
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
		return (addr >= start) && (((uintptr_t)addr + size) <= end);
	}
	return false;
}

bool Memory::Readable(uintptr_t addr, DWORD size)
{
	return CheckMemory(addr, READABLE, size);
}

bool Memory::Writable(uintptr_t addr, DWORD size)
{
	return CheckMemory(addr, WRITABLE, size);
}


void* Memory::CopyFunction(void* ptr, unsigned int size, bool bPopRax, bool bPushRax)
{
	bool b32Bit = (sizeof(void*) == 4) ? true : false;

	uint8_t* pNewFunction = (uint8_t*)malloc(size + 21);
	if (pNewFunction == 0)
		return 0;
	memset(pNewFunction, 0x90, size + 21);
	if(bPopRax)
		pNewFunction[0] = 0x58; // POP RAX

	memcpy(pNewFunction + 1, ptr, size);
	size += 1;


	/* Set JMPBack to the original function. */

	if (b32Bit) {
		pNewFunction[size + 0] = 0xE9;
		*(uintptr_t*)(pNewFunction + size + 1) = GetRelativeOffset<uintptr_t>((uintptr_t)ptr + size, (uintptr_t)pNewFunction + size);
	}
	else
	{
		// yikes >:(
		std::uintptr_t jmpbackAddy = (uintptr_t)ptr + (size - 2);

		if (bPushRax)
			pNewFunction[size + 0] = 0x50; // push rax :)
		else
			pNewFunction[size + 0] = 0x90; // nop
		pNewFunction[size + 1] = 0x48; pNewFunction[size + 2] = 0xb8; // mov rax, address
		memcpy(pNewFunction +size +  3, &jmpbackAddy, sizeof(jmpbackAddy)); // mov rax, address

		pNewFunction[size + 3 + sizeof(void*)] = 0xff; // jmp rax
		pNewFunction[size + 4 + sizeof(void*)] = 0xe0; // jmp rax
	}

	/* Set Execute permission, so we can execute the copied function */
	DWORD Old;
	VirtualProtect(pNewFunction, size + 22, PAGE_EXECUTE_READWRITE, &Old);

	return pNewFunction;
}

void* Memory::CreateCallRelay(void* to, bool bPopRax)
{
	bool b32Bit = (sizeof(void*) == 4) ? true : false;
	unsigned int size = (b32Bit) ? 5 : 15;

	uint8_t* pData = new uint8_t[size + 1];
	if (pData == 0)
		return nullptr;
	memset(pData, 0x90, size + 1);

	DWORD dwOld;
	VirtualProtect(pData, size + 1, PAGE_EXECUTE_READWRITE, &dwOld);

	if (b32Bit)
	{
		pData[0] = 0xE9;
		*(uintptr_t*)(pData + 1) = GetRelativeOffset<uintptr_t>((uintptr_t)to, (uintptr_t)pData, 5);
	}
	else
	{
		if (bPopRax)
			pData[0] = 0x58; // pop rax
		else
			pData[0] = 0x90; // nop

		pData[1] = 0x48; pData[2] = 0xb8; // mov rax, address
		memcpy(pData + 3, &to, sizeof(to)); // mov rax, address

		pData[3 + sizeof(void*)] = 0xff; // jmp rax
		pData[4 + sizeof(void*)] = 0xe0; // jmp rax
	}

	return pData;
}

void Memory::ReplaceRelativeOffset(void* dst, void* src)
{
	uintptr_t Address = Memory::GetRealAddress((uintptr_t*)src);
	*(uintptr_t*)dst = Memory::GetRelativeOffset<uintptr_t>(Address, (uintptr_t)dst, 4);
}

Process::MODULE Memory::SignatureScanner::GetModule(std::string const& modulename) const
{
	return m_process.GetModule(modulename);
}

bool Memory::SignatureScanner::CompareMemory(BYTE* bData, BYTE const* bMask, char const* szMask) const
{
	for (; *szMask; ++szMask, ++bData, ++bMask) {
		if (*szMask == 'x' && *bData != *bMask) {
			return false;
		}
	}
	return (*szMask == NULL);
}

uintptr_t Memory::SignatureScanner::Search(char const* sig, char const* mask)
{
	if (!m_module)
	{
		m_module = this->GetModule("");
	}
	if (m_process)
	{
		m_process.m_pid = GetCurrentProcessId();
		m_process.m_handle = GetCurrentProcess();
	}

	BYTE* bPtr = reinterpret_cast<BYTE*>(m_module.base);
	for (unsigned int index = 0; index < m_module.size; ++index)
	{

		if (CompareMemory((BYTE*)(bPtr + index), (BYTE*)sig, mask))
			return m_module.base + index;
	}
	return 0;
}

Process::PROCESS Memory::SignatureScanner::GetProcess(std::string const& processname) const
{
	return Process::GetProcess(processname, true);
}
