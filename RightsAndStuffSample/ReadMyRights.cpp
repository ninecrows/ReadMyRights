#include "ReadMyRights.h"
#include <stdio.h>

int
main(
	char** argv,
	int argc
)
{
	int result(0);

	printf("Starting up...\n");
	HANDLE process(GetCurrentProcess());
	printf("Got process handle 0x%08lx\n", process);

	HANDLE currentProcess = GetCurrentProcessToken();

	TOKEN_PRIVILEGES privs;
	LUID backupprivid;

	{
		BOOL ok = LookupPrivilegeValue(NULL,L"SeBackupPrivilege", &backupprivid);
		if (!ok)
			fprintf(stderr, "Failed to find backup: %lu\n", GetLastError());
	}

	LUID restoreprivid;
	{
		BOOL ok = LookupPrivilegeValue(NULL, L"SeRestorePrivilege", &restoreprivid);
		if (!ok)
			fprintf(stderr, "Failed to find restore: %lu\n", GetLastError());
	}

	
	
	if (process != NULL)
	{
		HANDLE token = NULL;
		BOOL ok = OpenProcessToken(process, TOKEN_READ, &token);

		if (ok)
		{
			printf("Opened token 0x%08lx\n", token);

			{
				PRIVILEGE_SET privs;
				privs.PrivilegeCount = 1;
				privs.Control = 0;
				privs.Privilege[0].Luid = backupprivid;
				privs.Privilege[0].Attributes = SE_PRIVILEGE_ENABLED;

				BOOL result = FALSE;
				BOOL ok = PrivilegeCheck(token, &privs, &result);
				if (!ok)
					fprintf(stderr, "Error in Priv check: %lu\n", GetLastError());
			}

			{
				TOKEN_PRIVILEGES tp;

				tp.PrivilegeCount = 1;
				tp.Privileges[0].Luid = backupprivid;
				tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

				BOOL ok = AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), NULL, NULL);
				if (!ok)
					fprintf(stderr, "Failed to add backup priv: %lu\n", GetLastError());
			}
		}
		else
		{
			fprintf(stderr, "Failed to open token %ld", GetLastError());
		}
	}
	else
	{
		fprintf(stderr, "Failed to open process %ld\n", GetLastError());
	}
	
	return result;
}