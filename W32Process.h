#ifndef W32PROCESS_H
#define W32PROCESS_H

#include <stdint.h>
#include <vector>
#include <string>
#include <assert.h>
#include <iostream>

#include "vex.h"


class W32Process
{
public:
	virtual ~W32Process();
	static W32Process* create(uint32_t pid);
	uint32_t getPID(void) const { return pid; }
	const std::string getExe(void) const
	{ assert (mods.size() > 0); return mods[0].mi_name; }
	unsigned getNumMods(void) const { return mods.size(); }
	HANDLE getHandle(void) { return proc_h; }

	uint64_t getEntry(void) const;
	unsigned getNumThreads(void) const { return threads.size(); }
	void writeThread(std::ostream& os, unsigned i) const;
	void writeMemory(const char* path) const;
	void writeSymbols(std::ostream& os) const;
protected:
	W32Process(uint32_t _pid);
private:
	bool writeMemoryRegion(
		const MEMORY_BASIC_INFORMATION*, std::ostream& os) const;
	void readMappings(void);
	void loadModules(void);
	void loadThreads(void);
	uint32_t	pid;
	HANDLE		proc_h;

struct modinfo
{
	std::string	mi_name;
	void		*mi_base;
	unsigned	mi_len;
};

	typedef std::vector<modinfo> modlist_ty;
	typedef std::vector<VexGuestX86State>	threadlist_ty;
	typedef std::vector<MEMORY_BASIC_INFORMATION*> mmaplist_ty;
	modlist_ty	mods;
	mmaplist_ty	mmaps;
	threadlist_ty	threads;
};

#endif
