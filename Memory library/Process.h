#pragma once

#include <Windows.h>
#include <stdint.h>
#include <string>
#include <TlHelp32.h>
#include <vector>

/* Process namespace */
namespace Process
{
	/* Process wrapper class */
	class PROCESS;
	
	/* Process memory module */
	class MODULE;

	/* Gets process by process name*/
	PROCESS GetProcess(std::string const& processname, bool openprocess = false, uint32_t processAccess = PROCESS_ALL_ACCESS);

	/* Gets process by process id */
	PROCESS GetProcess(int const& pid, bool openprocess = false, uint32_t processAccess = PROCESS_ALL_ACCESS);

	/* Returns all running processes */
	std::vector<PROCESS> GetProcesses();
}

/* Process class */
class Process::PROCESS
{
public:
	/* Attempts to kill process */
	bool kill() const;
	/* Checks if process is running */
	bool running() const;
	/* Opens process by process id */
	HANDLE open() const;
	/* Returns all process modules */
	std::vector<MODULE> GetModules() const;
	/* Gets process module by name */
	MODULE GetModule(std::string const& modulename) const;
	/* Returns true if process is 64 bit */
	bool Is64Bit() const;

	operator bool() const
	{
		return (m_handle != 0);
	}
public:
	uint32_t m_pid = 0;
	HANDLE m_handle = 0;
	std::string m_name;
private:
};


typedef struct {
	DWORD dwSize;
	DWORD GlblcntUsage;
	unsigned long long hModule;
	unsigned long long modBaseAddr;
	DWORD modBaseSize;
	DWORD ProccntUsage;
	WCHAR szExePath[260];
	WCHAR szModule[256];
	DWORD th32ModuleID;
	DWORD th32ProcessID;
	unsigned long long __unused;
}MODULE_ENTRY;


/* Module class */
class Process::MODULE
{
public:
	/* Returns address of symbol in module */
	uintptr_t GetAddress(std::string const& str);

	operator bool() const
	{
		return base != 0 && size > 0;
	}
public:
	std::string m_name;
	uintptr_t size = 0, base = 0;
private:
};