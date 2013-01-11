#include <windows.h>
#include <stdio.h>

int main(int argc, char* argv[])
{
	DEBUG_EVENT	de;
	DWORD		pids[4096], used_bytes;
	BOOL		ok;

	ok = EnumProcesses(pids, sizeof(pids), used_bytes);
	if (!ok) {
		fprintf(stderr, "Failed to enum processes\n");
		return -1;
	}

	for (unsigned i = 0; i < used_bytes/sizeof(DWORD); i++) {
		
	}

	ok = DebugActiveProcess(DWORD);
	if (!ok) {
		fprintf(stderr, "Failed to debug process\n");
		return -2;
	}

	ok = DebugBreakProcess(DWORD);

	WaitForDebugEvent(lpDebugEvent, INFINITE);

	ok = DebugActiveProcessStop();

	return 0;
}
