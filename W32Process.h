#ifndef W32PROCESS_H
#define W32PROCESS_H

#include <stdint.h>
#include <vector>
#include <string>
#include <assert.h>

class W32Process
{
public:
	virtual ~W32Process();
	static W32Process* create(uint32_t pid);
	uint32_t getPID(void) const { return pid; }
	const std::string getExe(void) const
	{ assert (mods.size() > 0); return mods[0]; }
	unsigned getNumMods(void) const { return mods.size(); }
	HANDLE getHandle(void) { return proc_h; }
protected:
	W32Process(uint32_t _pid);
private:
	void readMappings(void);
	void loadModules(void);
	uint32_t	pid;
	HANDLE		proc_h;
	typedef std::vector<std::string> modlist_ty;
	modlist_ty	mods;
	typedef std::vector<MEMORY_BASIC_INFORMATION*> mmaplist_ty;
	mmaplist_ty	mmaps;
};

#endif
