#include <windows.h>
#include <stdio.h>

//NOTE(): To compile this in cl, open up command prompt, run vcvars64.bat (located in program files (x86)/visual studio / year of Visual Studio / Community/VC / Auxiliary / Build ) and type in 
// cl.exe main.cpp user32.lib.


int main()
{
	FILE *shellcodeFile = NULL;
	size_t fileSize;
	int ret_val = 0;
	BYTE *code = NULL;

	shellcodeFile = fopen("shellcode.sc", "rb");

	if (shellcodeFile)
	{
		fseek(shellcodeFile,0,SEEK_END);
		fileSize = ftell(shellcodeFile);
		rewind(shellcodeFile);

		code = (BYTE*) VirtualAlloc(NULL, fileSize, MEM_COMMIT,PAGE_EXECUTE_READWRITE);

		fread(code,1,fileSize,shellcodeFile);

		int (*my_main)() = (int(*)()) ((ULONGLONG) code);
		ret_val = my_main();
	}
}
