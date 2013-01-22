#include <stdio.h>
#include <windows.h>
#include <winnt.h>
#include <ddk/ntapi.h>
#include <stdint.h>
#include <assert.h>
#include "slurp.h"


int main(int argc, char* argv[])
{
	unsigned i;
	BOOL	rc;
	STARTUPINFOA 		si;
	PROCESS_INFORMATION 	pi;
	char	ugh[512];

	ugh[0] = '\0';
	strcat(ugh, "7zx.exe ");
	for (i = 1; i < argc; i++) {
		if (i == 2) strcat(ugh, " -y ");
		strcat(ugh, "\"");
		strcat(ugh, argv[i]);
		strcat(ugh, "\" ");
	}

	memset(&si, 0, sizeof(si));
	memset(&pi, 0, sizeof(pi));
	si.cb = sizeof(si);

	rc = CreateProcess(
		NULL,
		ugh,
		NULL,
		NULL,
		FALSE, 
		CREATE_DEFAULT_ERROR_MODE,
		NULL,
		NULL, /* cwd... */
		&si, &pi);
	assert (rc != FALSE && "could not create process");

	WaitForSingleObject(pi.hProcess, (120 * 1000));
	CloseHandle(pi.hProcess);

	return 0;
}

