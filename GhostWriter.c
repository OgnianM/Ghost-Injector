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

#include "GhostWriter.h"


#define PUSHD 0x68 // push DWORD 
#define CALL_EAX 255, 208
#define MOVD_EAX 184
#define RET 195

uint32_t round_up(uint32_t x, uint32_t Boundry)
{
	return x + (Boundry - (x%Boundry));
}

byte WaitForThreadAutoLock(HANDLE Thread, PGHOSTWRITER Context)
{
	DWORD Esp = Context->WorkingThreadContext.Esp, i = 0;
	SetThreadContext(Thread, &Context->WorkingThreadContext);

	do
	{
		if (i == 100) return FALSE;
		while (ResumeThread(Thread) > 1) continue; // If the thread has been suspended multiple times
		Sleep(1);
		i++;
		SuspendThread(Thread);
		GetThreadContext(Thread, &Context->WorkingThreadContext);
	}
	while (Context->WorkingThreadContext.Eip != Context->JMPTOSELFAddress);
	Context->WorkingThreadContext.Esp = Esp;
	return TRUE;
}

// This routine will disassemble a possible "MOV [REG1],REG2" or "MOV [REG1+xx],REG2" instruction and validate its REG1 and REG2 registers so that:
//    a) They are EBX, EBP, ESI or EDI. We need them to be one of those, since they are the only stable ones when it comes to setting thread's context.
//    b) They are not the same ( REG1!=REG2 ). We need them to be different because we will use REG1 to point to memory and REG2 to write a DWORD.
//
int DisassembleAndValidateMOV(PUCHAR InstructionMemoryBase, ULONG* InstructionMemoryIndex, CONTEXT* PThreadContextBase, DWORD** WritePointer, DWORD** WriteItem, int* MOVRETOffsetFromMemoryRegister)
{
	UCHAR WritePointerRegIndex, WriteItemRegIndex, ModRM;
	DWORD* ArrayOfValidRegisterAddressesInContext[8];

	// Valid register addresses ( non-volatile ones ). NOTE, ESP is not volatile, but we will not be using it either.
	ArrayOfValidRegisterAddressesInContext[0] = NULL;    // EAX, not valid.
	ArrayOfValidRegisterAddressesInContext[1] = NULL;    // ECX, not valid.
	ArrayOfValidRegisterAddressesInContext[2] = NULL;    // EDX, not valid.
	ArrayOfValidRegisterAddressesInContext[3] = &PThreadContextBase->Ebx;    // EBX, valid, non-volatile, stable for setting it with setthreadcontext.
	ArrayOfValidRegisterAddressesInContext[4] = NULL;    // ESP, valid, but we will not use it.
	ArrayOfValidRegisterAddressesInContext[5] = &PThreadContextBase->Ebp;    // EBX, valid, non-volatile, stable for setting it with setthreadcontext.
	ArrayOfValidRegisterAddressesInContext[6] = &PThreadContextBase->Esi;    // ESI, valid, non-volatile, stable for setting it with setthreadcontext.
	ArrayOfValidRegisterAddressesInContext[7] = &PThreadContextBase->Edi;    // EDI, valid, non-volatile, stable for setting it with setthreadcontext.

	if (InstructionMemoryBase[*InstructionMemoryIndex] == 0x89)    // Is it a "MOV /r" instruction ?
	{
		ModRM = InstructionMemoryBase[*InstructionMemoryIndex + 1];    // if it is, we pick next byte, ModRM. We will diseminate it into Mod,dstRM,srcRM.

		if ((ModRM & 0x80) != 0)    // We need Mod field to be 00 or 01.
			return FALSE;

		WritePointerRegIndex = ModRM & 0x07;    // We pick dstRM ( destination register ).
		WriteItemRegIndex = (ModRM >> 3) & 0x07;    // We pick srcRM ( source register ).

		if (WritePointerRegIndex == WriteItemRegIndex)    // condition "b)", we need source and destination registers to be different REG1!=REG2.
			return FALSE;

		if ((ModRM & 0x40) == 0)    // if Mod field is 00, it is a "MOV [REG1],REG2" instruction. Otherwise, if it is 01, it is a "MOV [REG1+xx],REG2".
		{    // Mod == 00    =>    "MOV [REG1],REG2"
			if (WritePointerRegIndex == 5)    // This is a subcase of "MOV [REG1],REG2" that has to be discarded. When Mod is 00 and destination RM is
				return FALSE;            // 5 ( the value that would indicate EBP ), the instruction is not "MOV [EBP],REG2", it turns out to be
										 // "MOV [immediate32],REG2" instead. That immediate32 is a 32 bit address that gets encoded just after
										 // this ModRM byte ( 89 RM YY YY YY YY, or 89, ModRM byte, immediate32 dword ).

			*MOVRETOffsetFromMemoryRegister = 0;    // See Inject routine. This variable will hold the displacement over REG1 register. Since this is
													// is the case of a "MOV [REG1],REG2", there is no displacement over REG1, so we set it to 0.

			*InstructionMemoryIndex += 2;    // We increment the instruction memory index by 2, because that's the size of this instruction ( 89 RM ).
		}
		else
		{    // Mod == 01    =>    "MOV [REG1+xx],REG2"
			*MOVRETOffsetFromMemoryRegister = (signed char)InstructionMemoryBase[*InstructionMemoryIndex + 2];    // In this case, that "xx" of the
																												  // instruction is a byte and gets
																												  // encoded just after the ModRM byte
																												  // ( 89 RM xx ). So we pick it from
																												  // instruction memory and set it to
																												  // this variable as a sign extended
																												  // byte.
																												  // NOTE: MOVRETOffsetFromMemoryRegister
																												  // is a 32 bit integer while this "xx"
																												  // found in the instruction is a 8 bit
																												  // integer, thats why we sign extend it
																												  // by that cast, otherwise, it would not
																												  // work propperly in negative "xx" cases.

			*InstructionMemoryIndex += 3;    // As we have seen, the encoding of this case takes 3 bytes ( 89 RM xx ), so we increment instruction memory
											 // index by 3.
		}

		// If the picked registers are valid ( not NULL ), we set them to WritePointer and WriteItem.
		if ((ArrayOfValidRegisterAddressesInContext[WritePointerRegIndex] != NULL) && (ArrayOfValidRegisterAddressesInContext[WriteItemRegIndex] != NULL))
		{
			*WritePointer = ArrayOfValidRegisterAddressesInContext[WritePointerRegIndex];
			*WriteItem = ArrayOfValidRegisterAddressesInContext[WriteItemRegIndex];
		}
		else
			return FALSE;

		return TRUE;    // If we reach this point, all the needed requirements have been met.
	}
	else
		return FALSE;
}

byte InitGhostWriter(PGHOSTWRITER Context)
{
	memset(Context, 0, sizeof(GHOSTWRITER));

	byte* NtDLL = GetModuleHandleA("ntdll.dll");
	PIMAGE_DOS_HEADER NtDLL_DOS = NtDLL;
	PIMAGE_NT_HEADERS NtDLL_NT = NtDLL + NtDLL_DOS->e_lfanew;

	byte* NTDLLCode = NtDLL + NtDLL_NT->OptionalHeader.BaseOfCode;

	DWORD i = 0, j = 0, k = 0, NTDLLCodeSize = NtDLL_NT->OptionalHeader.SizeOfCode;                                            // sections in NTDLL.DLL ). We also assume those

	Context->NtReadVirtualMemory = GetProcAddress(NtDLL, "NtReadVirtualMemory");

#pragma region find patterns
	while ((i < NTDLLCodeSize) && ((!Context->JMPTOSELFAddress) || (!Context->MOVRETAddress)))    // While there is still machine code to look at and we have not found our
	{                                                                    // two needed patterns ( "JMP $" and "MOV [REG1],REG2"+"RET" ), keep searching
		if (!Context->JMPTOSELFAddress)    // If we still have not found a "JMP $"
		{
			if ((NTDLLCode[i] == 0xEB) && (NTDLLCode[i + 1] == 0xFE))    // check if we have that "JMP $" machine code at this point
			{
				Context->JMPTOSELFAddress = (DWORD)&NTDLLCode[i];    // If we found it, store the address for later usage
				i += 1;    // and increment searching index
			}
		}

		if (!Context->MOVRETAddress)    // If we still have not found a "MOV [REG1],REG2"+"RET"
		{    // check if it is a "MOV [REG1],REG2" or "MOV [REG1+xx],REG2". See DisassembleAndValidateMOV.
			if (DisassembleAndValidateMOV(NTDLLCode, &i, &Context->WorkingThreadContext, &Context->WritePointer, &Context->WriteItem, &Context->MOVRETOffsetFromMemoryRegister))
			{    // If the instruction was a valid ( see requirements criteria on DisassembleAndValidateMOV comments ) one,
				 // we have i pointing to the next opcode bytes after that MOV, WritePointer and WriteItem pointing to the correct register fields into
				 // WorkingThreadContext and MOVRETOffsetFromMemoryRegister set to the "xx" value in case the MOV instructions was "MOV [REG1+xx],REG2"

				j = i;
				k = 0;

				while (j < i + 16)    // in a 16 byte range after that MOV
				{
					if (((NTDLLCode[j] & 0xF8) == 0x58) && (NTDLLCode[j] != 0x5C))    // we look for POP REGx instructions
					{
						k += 4;    // if that's the case, we increment ESP balancing counter for later calculations.
						j += 1;    // We increment this subsearch index
						continue;    // and we continue with a new instruction byte
					}

					if ((NTDLLCode[j] == 0x83) && ((NTDLLCode[j + 1] & 0xF8) == 0xC0))    // we look for ADD REGx,yy
					{
						if (NTDLLCode[j + 1] == 0xC4)    // if that REGx is ESP,
							k += (signed char)NTDLLCode[j + 2];    // we add yy amount of bytes to ESP balancing counter for later use

						j += 3;    // We increment this subsearch index
						continue;    // and we continue with a new instruction byte
					}

					if ((NTDLLCode[j] == 0xC3) || ((NTDLLCode[j] == 0xC2) && (NTDLLCode[j + 2] == 0x00)))    // we look for a RET or RET n ( with n not above 255 )
					{                                                                            // if thats the case, we have found the second pattern
																								 // ( MOV + RET ).
						if (Context->MOVRETOffsetFromMemoryRegister == 0)    // if the MOV was a "MOV [REG1],REG2", then i variable was incremented by 2 ( the size
							Context->MOVRETAddress = (DWORD)&NTDLLCode[i - 2];    // of its machine code bytes ), so we set MOVRETAddress to NTDLLCode+i-2.
						else                                    // else, it was a "MOV [REG1+xx],REG2", so i variable was incremented by 3 ( the size
							Context->MOVRETAddress = (DWORD)&NTDLLCode[i - 3];    // of its machine code bytes ), so we set MOVRETAddress to NTDLLCode+i-3.

						Context->NumberOfBytesToPopBeforeRET = k;    // we set this variable to the amount accumulated into k ( value that will be added to
																	// ESP after the MOV gets executed and just before executing the RET ).

						i = j + 3;    // we increment i so that it points ahead this pattern
						break;    // and we finish the subsearch
					}
					break;    // if we reach a instruction that is not a POP REGx or ADD REGx,yy, we finish this subsearch
				}
			}
		}
		i++;    // increment i and keep looking for any "JMP $" or "MOV + RET"...
	}
#pragma endregion

	return (Context->JMPTOSELFAddress && Context->MOVRETAddress);
}


byte* GWGenerateCallingRoutine(uint32_t* size, uint32_t function, byte BytesToPopBeforeRet, PGHOSTWRITER Context, uint32_t* n_args, ...)
{
	*size = round_up((*n_args * 5) + 5 + 4, sizeof(DWORD)); /* Every arg takes up five bytes, 1 for the PUSH instr and 4 for the argument itself,\
																the extra 5 are for the MOV + the address \
																+ 2 bytes for CALL EAX \
																+ 5 bytes for MOV ESP, X \
																+ 1 byte for RET \
																DWORD aligned for the injector */
	byte* Caller = malloc(*size);

	uint32_t CallerPos = 0, *arg = n_args + 1;

	for (uint32_t i = 0; i < *n_args; i++)
	{
		Caller[CallerPos] = PUSHD;
		CallerPos++;
		memcpy(Caller + CallerPos, arg, sizeof(DWORD));
		CallerPos += sizeof(DWORD);
		arg++;
	}


	Caller[CallerPos] = MOVD_EAX; // MOV EAX, 
	CallerPos++;
	memcpy(Caller + CallerPos, &function, sizeof(DWORD)); // Address
	CallerPos += sizeof(DWORD);

	Caller[CallerPos++] = 255; //CALL
	Caller[CallerPos++] = 208; // EAX
	//131 196 - add esp !unused
	//188 MOV ESP 
	Caller[CallerPos++] = 188; // MOV ESP

	DWORD AdjustedESP = Context->WorkingThreadContext.Esp + Context->NumberOfBytesToPopBeforeRET;

	memcpy(Caller + CallerPos, &AdjustedESP, 4);
	CallerPos += 4;
	Caller[CallerPos++] = RET;
	return Caller;
}

void ModifyCallingRoutineArgument(byte* Routine, uint32_t ArgumentIndex, uintxx_t NewValue)
{
	*((uintxx_t*)(Routine + (ArgumentIndex*4) + ArgumentIndex + 1)) = NewValue;
}


byte GWPrepareThread(HANDLE Thread, PGHOSTWRITER Context)
{
	byte Result;
	SuspendThread(Thread);
	
	memset(&Context->SavedThreadContext, 0, sizeof(CONTEXT));
	memset(&Context->WorkingThreadContext, 0, sizeof(CONTEXT));
	
	Context->WorkingThreadContext.ContextFlags = CONTEXT_ALL;
	Context->SavedThreadContext.ContextFlags = CONTEXT_ALL;
	GetThreadContext(Thread, &Context->WorkingThreadContext);
	GetThreadContext(Thread, &Context->SavedThreadContext);
	if ((Context->JMPTOSELFAddress) && (Context->MOVRETAddress))
	{
		*Context->WritePointer = Context->WorkingThreadContext.Esp; // WritePointer is the bottom of the stack
		*Context->WriteItem = Context->JMPTOSELFAddress; // WriteItem is the JMPTOSelfAddress
		Context->WorkingThreadContext.Esp -= Context->NumberOfBytesToPopBeforeRET; // push the number of bytes that will be popped after mov
		Context->WorkingThreadContext.Eip = Context->MOVRETAddress;
		Result = WaitForThreadAutoLock(Thread, Context); // Write!
		//if (!Result) GWResumeThread(Thread, Context);
		return Result;
	}
	return FALSE;
}

DWORD GWResumeThread(HANDLE Thread, PGHOSTWRITER Context)
{
	SetThreadContext(Thread, &Context->SavedThreadContext);
	return ResumeThread(Thread);
}

int GWriteMemory(HANDLE Thread, DWORD* InjectionCode, ULONG NumberOfDWORDsToInject, PBYTE pBaseOfInjected, PGHOSTWRITER Context)
{
	DWORD i = 0, DWORDWritingPointer = pBaseOfInjected;
	if ((Context->JMPTOSELFAddress) && (Context->MOVRETAddress))
	{
		for (i = 0; i < NumberOfDWORDsToInject; i++)
		{
			*Context->WritePointer = DWORDWritingPointer - Context->MOVRETOffsetFromMemoryRegister;
			*Context->WriteItem = InjectionCode[i];
			Context->WorkingThreadContext.Eip = Context->MOVRETAddress;
			WaitForThreadAutoLock(Thread, Context);
			DWORDWritingPointer += sizeof(DWORD);
		}
		return TRUE;    // all went fine :D
	}
	return FALSE;
}

uintxx_t GWCall(HANDLE hThread, DWORD dwFunction, PVOID RemoteCallerBuffer, PGHOSTWRITER Context, uint32_t n_args, ...)
{
	uint32_t CallerSize;
	byte* CallerCode = GWGenerateCallingRoutine(&CallerSize, dwFunction, 4, Context, &n_args);
	GWriteMemory(hThread, CallerCode, CallerSize, RemoteCallerBuffer, Context);
	Context->WorkingThreadContext.Eip = RemoteCallerBuffer;
	WaitForThreadAutoLock(hThread, Context);
	return Context->WorkingThreadContext.Eax;
}

HANDLE GetThisProcessDuplicated(HANDLE hTarget)
{
	HANDLE hThis = GetCurrentProcess(), hDuplicated;
	DuplicateHandle(hThis, hThis, hTarget, &hDuplicated, PROCESS_ALL_ACCESS, FALSE, 0);
	CloseHandle(hThis);
	return hDuplicated;
}