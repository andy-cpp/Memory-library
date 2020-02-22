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

public:
	uint32_t m_pid = 0;
	HANDLE m_handle = 0;
	std::string m_name;
private:
};


/* Module class */
class Process::MODULE
{
public:
	/* Returns address of symbol in module */
	DWORD GetAddress(std::string const& str);


public:
	std::string m_name;
	DWORD dwSize = 0, dwBase = 0;
private:
};