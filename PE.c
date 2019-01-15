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


#include "PE.h"


PIMAGE_SECTION_HEADER GetSectionOfVA(PE* pe, uint32_t VA)
{
	for(int i = 0; i < pe->NTHeaders->FileHeader.NumberOfSections; i++)
	{
		// Find which section the IAT VA points to and get it's physical address using some fancy math.
		if (INRANGE(pe->SectionHeaders[i].VirtualAddress, round_up(pe->SectionHeaders[i].VirtualAddress +
																	 pe->SectionHeaders[i].Misc.VirtualSize, pe->NTHeaders->OptionalHeader.SectionAlignment), VA))
		{
			return &pe->SectionHeaders[i];
		}
	}
	return 0;
}

PIMAGE_SECTION_HEADER GetCodeSection(PE* pe)
{
	return GetSectionOfVA(pe, pe->NTHeaders->OptionalHeader.BaseOfCode);
}

uintxx_t rva2phys(PE* pe, uintxx_t VA)
{
	PIMAGE_SECTION_HEADER Header = GetSectionOfVA(pe, VA);
	if (!Header) return 0;
	return pe->File + Header->PointerToRawData + (VA - Header->VirtualAddress);
}



int InitPE(PE* pe, byte* Data, uint32_t Size)
{
	pe->File = Data;
	if (Size)
		pe->Size = Size;
	pe->VirtualImage = FALSE;
	if (!Data) return PE_ERR_INVALID_BUFFER;

	pe->DOSHeader = (PIMAGE_DOS_HEADER)Data;
	pe->NTHeaders = (PIMAGE_NT_HEADERS)(Data + pe->DOSHeader->e_lfanew);
	pe->SectionHeaders = pe->NTHeaders + 1;

	if (pe->NTHeaders->OptionalHeader.Magic == 0x10b) pe->x64 = FALSE;
	else if (pe->NTHeaders->OptionalHeader.Magic == 0x20b) pe->x64 = TRUE;
	else return PE_ERR_INVALID_MAGIC;

	return PE_SUCCESS;
}

void FreePE(PE* pe)
{
	free(pe->File);
	free(pe->SectionHeaders);
}


void BuildIAT(PE* pe)
{
	PIMAGE_SECTION_HEADER CurrentHeader;
	uint32_t* IDT_entry = (uint32_t*)rva2phys(pe, pe->NTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	if (IDT_entry)
	{
		PIMAGE_IMPORT_DESCRIPTOR ImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)IDT_entry;
		HMODULE CurrentLibrary;
		uint32_t* LookupEntry, LookupName;


		while (TRUE) // Build payload IAT
		{
			CurrentLibrary = LoadLibraryA(rva2phys(pe, ImportDescriptor->Name));

			for (LookupEntry = (uint32_t*)rva2phys(pe, ImportDescriptor->FirstThunk); *LookupEntry; LookupEntry++)
			{
				LookupName = rva2phys(pe, (uint32_t)(((char*)*LookupEntry) + 2)); // Pointer to the physical offset of the function name
				*LookupEntry = GetProcAddress(CurrentLibrary, LookupName); // Sets the entry to the actual function
			}

			FreeLibrary(CurrentLibrary);

			ImportDescriptor++;

			if (!ImportDescriptor->Characteristics && !ImportDescriptor->FirstThunk && !ImportDescriptor->TimeDateStamp &&
				!ImportDescriptor->ForwarderChain && !ImportDescriptor->Name && !ImportDescriptor->OriginalFirstThunk)
				break;
		}
	}
}


bool Relocate(PE* pe, uintxx_t NewBase)
{
	PIMAGE_BASE_RELOCATION RelocHeader = (PIMAGE_BASE_RELOCATION)pe->NTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;

	if (pe->VirtualImage) RelocHeader = (PIMAGE_BASE_RELOCATION)(pe->File + (uint32_t)RelocHeader);
	else RelocHeader = (PIMAGE_BASE_RELOCATION)rva2phys(pe,(uint32_t)RelocHeader);

	if (!RelocHeader) return FALSE;

	uint32_t RelocationBlockSize, Delta = NewBase - pe->NTHeaders->OptionalHeader.ImageBase,
		SizeOfRelocationSection = pe->NTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size,
		ZeroBasedVirtualAddress, *CurrentMajorAddress;

	PIMAGE_SECTION_HEADER CurrentSection, CodeSection = GetCodeSection(pe);

	byte* RelocationBlock = (byte*)(RelocHeader + 1);
	WORD RelocType, RVA;
	uint32_t *AbsoluteRVA;


	while (TRUE)
	{
		CurrentSection = GetSectionOfVA(pe, RelocHeader->VirtualAddress);

		if (!CurrentSection) break;

		RelocationBlockSize = RelocHeader->SizeOfBlock / 2;
		RelocationBlockSize -= 4;
		ZeroBasedVirtualAddress = RelocHeader->VirtualAddress - CurrentSection->VirtualAddress;
		CurrentMajorAddress = (uint32_t*)(pe->File +
			(pe->VirtualImage ? RelocHeader->VirtualAddress :
			 ZeroBasedVirtualAddress + CurrentSection->PointerToRawData));

		for(int i = 0; i < RelocationBlockSize; i++)
		{
			RelocType = ((WORD*)RelocationBlock)[i] & 0xf000;
			RelocType >>= 12;
			RVA = ((WORD*)RelocationBlock)[i] & 0xfff;

			switch (RelocType)
			{
				case IMAGE_REL_BASED_ABSOLUTE:
				{
					continue;
				}
				case IMAGE_REL_BASED_HIGHLOW:
				{
					AbsoluteRVA = (uint32_t*)((byte*)CurrentMajorAddress + RVA);// += Delta;
					*AbsoluteRVA += Delta;
					break;
				}
				default:
				{
					//DEBUG("Unsupported relocation of type %d in block %d\n", type, reloc_header->VirtualAddress);
					continue;
				}
			}
		}

		RelocationBlock += RelocHeader->SizeOfBlock;
		RelocHeader = (PIMAGE_BASE_RELOCATION)(RelocationBlock - sizeof(IMAGE_BASE_RELOCATION));
		if (!RelocHeader->SizeOfBlock) break;
	}
	pe->NTHeaders->OptionalHeader.ImageBase = NewBase;
	return TRUE;
}
