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

byte ReflectiveInject(HANDLE hProcess, HANDLE hThread, PE* pe, int Flags, PGHOSTWRITER Context)
{
	if (hProcess == INVALID_HANDLE_VALUE)
		return INJECTOR_ERR_INVALID_PROCESS;

	if (Flags & INJECTOR_BUILD_IAT)
		BuildIAT(pe);

	
	PVOID RemoteImage = VirtualAllocEx(hProcess, NULL, pe->NTHeaders->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!RemoteImage) return INJECTOR_ERR_FAILED_ALLOCATION;

	PVOID RemoteCaller = VirtualAllocEx(hProcess, NULL, 256, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!RemoteCaller)
	{
		VirtualFreeEx(hProcess, RemoteImage, pe->NTHeaders->OptionalHeader.SizeOfImage, MEM_RELEASE);
		return INJECTOR_ERR_FAILED_ALLOCATION;
	}

	Relocate(pe, RemoteImage);

	PIMAGE_SECTION_HEADER SectionHeader;
	DWORD dwBytesWritten = 0, dwNewProtect = 0;
	HANDLE hThis;

	if (hThread == INVALID_HANDLE_VALUE)
	hThread = CreateRemoteThread(hProcess, NULL, NULL, NULL, NULL, CREATE_SUSPENDED, NULL);

	if (hThread == INVALID_HANDLE_VALUE) goto fail;
	if (!GWPrepareThread(hThread, Context)) goto fail;

	hThis = GetThisProcessDuplicated(hProcess);


	if (Flags & INJECTOR_VIRTUAL_IMAGE)
	{
		// Inject the whole thing in one call, preferable, since its faster
		if (GWRemoteReadVirtualMemory(hThread, RemoteCaller, Context, hThis, pe->File, RemoteImage,
									  pe->NTHeaders->OptionalHeader.SizeOfImage, RemoteImage) == -1)
			goto fail;
	}
	else
	{
		// Might be useless, since data in PE headers is pretty much only used by the loader
		if (GWRemoteReadVirtualMemory(hThread, RemoteCaller, Context, hThis, pe->File, RemoteImage,
									  pe->NTHeaders->OptionalHeader.SizeOfHeaders, RemoteImage) == -1) goto fail;

		for (int i = 0; i < pe->NTHeaders->FileHeader.NumberOfSections; i++)
		{
			SectionHeader = &pe->SectionHeaders[i];

			if (GWRemoteReadVirtualMemory(hThread, RemoteCaller, Context, hThis, pe->File + SectionHeader->PointerToRawData,
				(uintxx_t)RemoteImage + SectionHeader->VirtualAddress, SectionHeader->Misc.VirtualSize, RemoteImage) == -1) goto fail;
		}
	}

	if (Flags & INJECTOR_FIX_PROTECT)
	for(int i = 0; i < pe->NTHeaders->FileHeader.NumberOfSections; i++)
	{
		SectionHeader = &pe->SectionHeaders[i];

		if (SectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE) dwNewProtect = PAGE_EXECUTE_READ;
		else if (SectionHeader->Characteristics & IMAGE_SCN_MEM_READ)
		{
			if (SectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE) dwNewProtect = PAGE_READWRITE;
			else dwNewProtect = PAGE_READONLY;
		}
		else if (SectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE) dwNewProtect = PAGE_WRITECOPY;
		VirtualProtectEx(hProcess, (uint32_t)RemoteImage + SectionHeader->VirtualAddress,
						  round_up(SectionHeader->Misc.VirtualSize, pe->NTHeaders->OptionalHeader.SectionAlignment), dwNewProtect, &dwBytesWritten);
	}

	if (Flags & INJECTOR_AUTO_RUN)
	{
		Context->WorkingThreadContext.Eip = pe->NTHeaders->OptionalHeader.AddressOfEntryPoint + (uint32_t)RemoteImage;
		SetThreadContext(hThread, &Context->WorkingThreadContext);
		ResumeThread(hThread);
	}

	VirtualFreeEx(hProcess, RemoteCaller, 256, MEM_RELEASE);
	return TRUE;
fail:
	VirtualFreeEx(hProcess, RemoteImage, pe->NTHeaders->OptionalHeader.SizeOfImage, MEM_RELEASE);
	VirtualFreeEx(hProcess, RemoteCaller, 256, MEM_RELEASE);
	TerminateThread(hThread, 0);
	CloseHandle(hThread);
	return FALSE;
}
