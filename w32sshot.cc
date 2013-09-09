#define _WIN32_WINNT 0x501
#include <stdio.h>
#include <iostream>
#include <windows.h>
#include <psapi.h>
#include <unistd.h>
#include <assert.h>
#include <iostream>
#include <fstream>
#include "W32Process.h"
	
/* ripped from vexllvm code */
#define VEXLLVM_ARCH_I386	3

#define INIT_FILE(x)				\
	sprintf(f_path, "%s/" #x, path);	\
	f = fopen(f_path, "w");			\
	if (!f) return false;

bool dumpProcess(W32Process* w32p, const char* path)
{
	FILE*		f;
	char		f_path[MAX_PATH];
	uint64_t	entry_addr;

	if (mkdir(path) != 0) {
		std::cerr << "FAILED TO MAKE PATH: " << path << '\n';
		return false;
	}

	INIT_FILE(binpath);
	fwrite(	w32p->getExe().c_str(),
		w32p->getExe().size(),
		1,
		f);
	fclose(f);

	std::cerr << "[DUMP] NO ARGC!!!\n";
	std::cerr << "[DUMP] NO ARGV!!!\n";
	INIT_FILE(argv)
	fclose(f);
	INIT_FILE(argc)
	fclose(f);

	INIT_FILE(dynsyms)
	fclose(f);


	uint32_t arch = VEXLLVM_ARCH_I386;
	INIT_FILE(arch);
	fwrite(&arch, sizeof(arch), 1, f);
	fclose(f);


	/* entry point */
	entry_addr = w32p->getEntry();
	INIT_FILE(entry);
	fwrite(&entry_addr, sizeof(entry_addr), 1, f);
	fclose(f);

	assert (w32p->getNumThreads());

	w32p->writeThreads(path);

	w32p->writeMemory(path);

	sprintf(f_path, "%s/syms", path);
	std::ofstream* ofp = new std::ofstream(f_path, std::ios::binary);
	w32p->writeSymbols(*ofp);
	delete ofp;

	sprintf(f_path, "%s/platform", path);
	mkdir(f_path);
	w32p->writePlatform(f_path);

	return true;
}


static std::string path_basename(const char* path)
{
	const char	*last_elem(strrchr(path, '\\'));
	return (last_elem == NULL)
		? path
		: last_elem;
}

static W32Process* getRunningProcess(const char* path)
{
	W32Process	*w32p;
	DWORD		pids[4096], used_bytes;
	std::string	name;
	BOOL		ok;

	name = path_basename(path);

	ok = EnumProcesses(pids, sizeof(pids), &used_bytes);
	if (!ok) {
		DWORD	err = GetLastError();
		std::cerr << "Failed to EnumProcesses. Err=" << err << "\n";
		SetLastError(0);
		return NULL;
	}

	for (unsigned i = 0; i < used_bytes/sizeof(DWORD); i++) {
		w32p = W32Process::create(pids[i]);
		if (w32p == NULL) {
			std::cerr << "[W32Process] Could not open process for pid="
				<< pids[i] << '\n';
			continue;
		}

		if (w32p->getNumMods() <= 0)
			goto ignore;

		if (path != NULL) {
			if (path_basename(w32p->getExe().c_str()) == name)
				break;
		} else
			std::cout << w32p->getExe() << '\n';
ignore:
		delete w32p;
		w32p = NULL;
	}

	return w32p;
}

int main(int argc, char* argv[])
{
	DEBUG_EVENT	de;
	W32Process	*w32p;
	BOOL		ok;

	w32p = getRunningProcess((argc <= 1) ? NULL: argv[1]);
	if (argc < 2)
		return 0;

	if (w32p == NULL) {
		std::cerr
			<< "Could not find "
			<< argv[1] << ". Is process running?\n";
		return -2;
	}

	w32p->slurpAll();

	std::cout << "Debugging: " << w32p->getExe() << '\n';
	ok = DebugActiveProcess(w32p->getPID());
	if (!ok) {
		std::cerr << "Failed to debug process\n";
		return -2;
	}

	std::cerr << "Breaking process\n";
	ok = DebugBreakProcess(w32p->getHandle());
	WaitForDebugEvent(&de, INFINITE);

	dumpProcess(w32p, "snapshot");

	std::cerr << "Restoring control to process\n";
	ok = DebugActiveProcessStop(w32p->getPID());

	delete w32p;
	return 0;
}
