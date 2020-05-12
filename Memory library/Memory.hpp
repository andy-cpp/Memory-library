#pragma once

#include "Process.h"
#include "Hooks.h"

namespace Memory
{
	/* Memory constants */
	constexpr auto READABLE = (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY);
	constexpr auto WRITABLE = (PAGE_WRITECOMBINE | PAGE_WRITECOPY | PAGE_READWRITE | PAGE_EXECUTE_READWRITE);

	/* Process Namespace */
	namespace Process = Process;
	
	/* Hooks Namespace */
	namespace Hooks = Hooks;

	/* SignatureScanner class */
	class SignatureScanner;

	/* Returns true if the page has the certain access flags specified*/
	bool CheckMemory(uintptr_t addr, uint32_t access, DWORD size = 1);

	/* Returns true if memory is readable */
	bool Readable(uintptr_t addr, DWORD size = 1);

	/* Returns true if memory  is writable */
	bool Writable(uintptr_t addr, DWORD size = 1);

	/* Two's Complement template */
	template <typename T>
	T TwosComplement(T const& number, typename std::enable_if<std::is_unsigned<T>::value>::type* = 0)
	{
		return ~(uintptr_t)number + 1;
	}

	/* Calculates relative offset, size is instruction size */
	template <typename T>
	T GetRelativeOffset(T to, T from, DWORD size = 5)
	{
		auto value = (to - from) - (uintptr_t)size;
		return (T)value;
	}

	/* Calculates the real address of a relative offset */
	template <typename T>
	T GetRealAddress(T* relativeOffset)
	{
		return (DWORD)((intptr_t)relativeOffset - (TwosComplement(*(uintptr_t*)relativeOffset)));
	}

	/* Copies function, returns pointer to the copied function
		@param bPopRax (only for 64 bit) - decides whether you push rax before jumping back to function.
		@param bPushRax (only for 64 bit) - decides whether you pop rax before on function start
	*/
	void* CopyFunction(void* ptr, unsigned int size = 5, bool bPopRax = false, bool bPushRax = true);

	/* Creates call relay 
		@param to - where to jmp / call
		@param bPopRax (64 bit only) - decides whether you pop rax or not
	*/
	void* CreateCallRelay(void* to, bool bPopRax = false);

	/* Replace relative offsets function */
	void ReplaceRelativeOffset(void* dst, void* src);
}



class Memory::SignatureScanner
{
public:
	
	uintptr_t Search(char const* sig, char const* mask);

	Process::PROCESS GetProcess(std::string const& processname) const;
	Process::MODULE GetModule(std::string const& modulename) const;
public:
	Process::PROCESS m_process;
	Process::MODULE m_module;
private:
	bool CompareMemory(BYTE* bByte, BYTE const* sig, char const* mask) const;
};