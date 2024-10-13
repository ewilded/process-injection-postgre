// How to compile:
// 1. Initialize the Visual Studio compiler environment by calling the vcvars script (adjust your path accordingly, depending on your version):
// c:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat
// 2. Run cl.exe on the source file, like this:
// cl.exe /D_USRDLL /D_WINDLL /MT /Tc basic_info.c /link /DLL /out:basic_info.dll /SUBSYSTEM:WINDOWS /MACHINE:x64

#include "dll.h"
#include <windows.h>
#pragma comment(lib,"kernel32.lib")
#pragma comment(lib,"advapi32.lib")

BOOL APIENTRY DllMain( HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
	if(ul_reason_for_call == DLL_PROCESS_ATTACH)
	{
		char user_name[104];
		memcpy(user_name, "", 104);
		char module_fname[MAX_PATH];
		memcpy(module_fname, "", MAX_PATH);
		LPSTR command_line = GetCommandLineA();
		GetModuleFileNameA(NULL, module_fname, MAX_PATH);
		HANDLE hFile = CreateFileA("C:\\users\\Public\\get_basic_info.txt", GENERIC_WRITE, FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		DWORD max_user_name = 104;
		GetUserNameA(user_name, &max_user_name);

		DWORD bytesWritten; char lf[] = "\n"; char left_bracket[] = " [ "; char right_bracket[] = " ] ";
		if (hFile != INVALID_HANDLE_VALUE)
		{
			SetFilePointer(hFile, 0, NULL, FILE_END);
			WriteFile(hFile, module_fname, strlen(module_fname), &bytesWritten, NULL);
			WriteFile(hFile, left_bracket, strlen(left_bracket), &bytesWritten, NULL);
			WriteFile(hFile, command_line, strlen(command_line), &bytesWritten, NULL);
			WriteFile(hFile, right_bracket, strlen(left_bracket), &bytesWritten, NULL);
			WriteFile(hFile, left_bracket, strlen(left_bracket), &bytesWritten, NULL);
			WriteFile(hFile, user_name, strlen(user_name), &bytesWritten, NULL);
			WriteFile(hFile, right_bracket, strlen(left_bracket), &bytesWritten, NULL);
			WriteFile(hFile, lf, 1, &bytesWritten, NULL);
			CloseHandle(hFile);
		}
	}
	return TRUE;
}
