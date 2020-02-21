#pragma once

#include "Process.h"

namespace Memory
{
	/* Memory constants */
	constexpr auto READABLE = (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY);
	constexpr auto WRITABLE = (PAGE_WRITECOMBINE | PAGE_WRITECOPY | PAGE_READWRITE | PAGE_EXECUTE_READWRITE);

	/* Process Namespace */
	namespace Process = Process;

	/* Returns true if the page has the certain access flags specified*/
	bool CheckMemory(DWORD addr, uint32_t access, DWORD size = 1);

	/* Returns true if memory is readable */
	bool Readable(DWORD addr, DWORD size = 1);

	/* Returns true if memory  is writable */
	bool Writable(DWORD addr, DWORD size = 1);


	
	/* Two's Complement template */
	template <typename T>
	T TwosComplement(T const& number)
	{
		return (~number) + 1;
	}


}


