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

#pragma once
#include <Windows.h>

typedef unsigned long uint32_t;

typedef uint32_t uintxx_t;

typedef struct GHOSTWRITER_CTX
{
	CONTEXT WorkingThreadContext;
	CONTEXT SavedThreadContext;
	uintxx_t* WritePointer;
	uintxx_t* WriteItem;
	uintxx_t MOVRETAddress;
	uintxx_t JMPTOSELFAddress;
	uintxx_t MOVRETOffsetFromMemoryRegister;
	uintxx_t NtReadVirtualMemory;
	uint32_t NumberOfBytesToPopBeforeRET;
} GHOSTWRITER, *PGHOSTWRITER;


byte InitGhostWriter(PGHOSTWRITER Context);
byte GWPrepareThread(HANDLE Thread, PGHOSTWRITER Context);
DWORD GWResumeThread(HANDLE Thread, PGHOSTWRITER Context);
int GWriteMemory(HANDLE Thread, DWORD* InjectionCode, ULONG NumberOfDWORDsToInject, PBYTE pBaseOfInjected, PGHOSTWRITER Context);
uintxx_t GWCall(HANDLE hThread, DWORD dwFunction, PVOID RemoteCallerBuffer, PGHOSTWRITER Context, uintxx_t n_args, ...);
//byte* GWGenerateCallingRoutine(uint32_t* size, uint32_t function, uint16_t BytesToPopBeforeRet, GLOBALS* globals, uint32_t n_args, ...);
HANDLE GetThisProcessDuplicated(HANDLE hTarget);
uint32_t round_up(uint32_t x, uint32_t Boundry);

/*
	Note: Local arguments are those which will be used internally, by the algorithm,
		  Remote arguments are those which will be passed on to the function called in the target process

	hThread			[in, local] The thread doing the reading
	pRemoteCaller	[in, local] A buffer allocated for the caller of NtReadVirtualMemory, used internally
	Context			[in, local] A valid GHOSTWRITER context
	hProcess		[in, remote] A duplicated handle of this process (or any process from which you want your target to read) see DuplicateHandle
	BaseAddress		[in, remote] The local address from which to read (remember to think as if you *are* the other process)
	Buffer			[in, remote] The remote buffer into which the data will be read
	Size			[in, remote] The number of bytes to read
	BytesWritten	[in, remote] A pointer to a buffer which receives the BytesWritten, NtReadVirtualMemory requires it and you have to make sure,
								you have a valid remote buffer into which this value can be written
*/
#define GWRemoteReadVirtualMemory(hThread, pRemoteCaller, Context, hProcess, BaseAddress, Buffer, Size, BytesWritten)\
 GWCall(hThread, (Context)->NtReadVirtualMemory, pRemoteCaller, Context, 5, BytesWritten, Size, Buffer, BaseAddress, hProcess)



/*
	Further notes:
	If you want to be *super* stealthy, use one of the application's own threads, don't create a new one.
	After you've injected your code, you can create a new thread internally to serve as a replacement to the
	one you've hijacked.

	If you can find RWE memory in the target, you can also write your stups right in there so as to replace
	VirtualAllocEx with a local VirtualAlloc, might crash the target though
*/