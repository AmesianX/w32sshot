#include <stdio.h>
#include <windows.h>
#include <winnt.h>
#include <ddk/ntapi.h>
#include <stdint.h>
#include <assert.h>
#include "slurp.h"

static void slurpData(void);

/**
 * A DLL for reading off process information. Because that's Windows.
 * Install in C:\slurp.dll
 */

/*__declspec(dllexport)*/  BOOL WINAPI DllMain(
	HINSTANCE hinstDLL,
	DWORD fdwReason,
	LPVOID lpvReserved)
{
	if (fdwReason != DLL_PROCESS_ATTACH) return 0;

	slurpData();
	/* fail it so we don't stay resident. */
	return 0;
}


static void slurpData(void)
{
	DWORD			rc, br;
	struct slurp_w32	s;
	HANDLE			pipe_h;

	rc = NtQueryInformationProcess(
		NtCurrentProcess(),
		(PROCESSINFOCLASS)36 /* ProcessCookie */,
		&s.cookie,
		sizeof(s.cookie),
		NULL);
	assert (rc == STATUS_SUCCESS && "Bad QueryInformationProcess");

	rc = WaitNamedPipe(SLURP_PIPE, NMPWAIT_WAIT_FOREVER);
	assert (rc != FALSE);

	pipe_h = CreateFile(
		SLURP_PIPE, GENERIC_WRITE, 0, NULL,
		OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL, NULL);
	assert (pipe_h != NULL && "COULD NOT OPEN PIPE");
	rc = WriteFile(pipe_h, &s, sizeof(s), &br, NULL);
	assert (br == sizeof(s));
	assert (rc != FALSE && "BAD PIPE WRITE");
}
