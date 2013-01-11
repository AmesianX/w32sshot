#include <windows.h>
#include <psapi.h>
#include <stdio.h>
#include <unistd.h>
#include "Sugar.h"

#include "W32Process.h"

W32Process::W32Process(uint32_t _pid)
: pid(_pid)
{
	proc_h = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	loadModules();
	readMappings();
}

void W32Process::readMappings(void)
{
	void*	addr;

	addr = NULL;
	/* I don't know what the user/kernel split is. fuck it */
	while ((uintptr_t)addr < 0xc0000000) {
		MEMORY_BASIC_INFORMATION	mbi, *mmap_mbi;
		SIZE_T				sz;

		sz = VirtualQueryEx(proc_h, addr, &mbi, sizeof(mbi));
		if (sz != sizeof(mbi)) 
			break;

		/* bump addr to next avail region */
		addr = (void*)((uintptr_t)mbi.BaseAddress + mbi.RegionSize);

		/* ignore free regions; nothing to store */
		if (mbi.State == MEM_FREE)
			continue;

		/* found a useful region, remember it */
		mmap_mbi = new MEMORY_BASIC_INFORMATION(mbi);
		mmaps.push_back(mmap_mbi);
	}
}

void W32Process::loadModules(void)
{
	BOOL		ok;
	DWORD		used_bytes;
	HMODULE		hmods[1024];

	ok = EnumProcessModules(proc_h, hmods, sizeof(hmods), &used_bytes);
	if (!ok)
		return;

	for (unsigned i = 0; i < used_bytes / sizeof(HMODULE); i++) {
		TCHAR	name[MAX_PATH];

		ok = GetModuleFileNameEx(
			proc_h, hmods[i], name, sizeof(name)/sizeof(TCHAR));
		if (!ok)
			continue;

		mods.push_back(name);
	}
}

W32Process::~W32Process(void)
{
	if (proc_h != NULL)
		CloseHandle(proc_h);

	foreach (it, mmaps.begin(), mmaps.end())
		delete (*it);
}

W32Process* W32Process::create(uint32_t pid)
{
	W32Process	*ret;

	ret = new W32Process(pid);
	if (ret->proc_h == NULL)
		goto fail;

	return ret;
fail:
	delete ret;
	return NULL;
}
