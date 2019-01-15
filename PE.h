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
#include "GhostWriter.h"

#define PE_SUCCESS 0
#define PE_ERR_INVALID_BUFFER -1
#define PE_ERR_INVALID_MAGIC -1

#define INRANGE(a, b, x) ((x >= a) && (x < b))


typedef unsigned short uint16_t;
typedef byte bool;
/*
Custom PE holder
*/
typedef struct PortableExecutable
{
	byte* File;
	uint32_t Size;
	PIMAGE_DOS_HEADER DOSHeader;
	PIMAGE_NT_HEADERS NTHeaders;
	uint32_t PhysicalEntryPoint;
	PIMAGE_SECTION_HEADER SectionHeaders;
	bool x64;
	bool VirtualImage;
} PE;

int InitPE(PE* pe, char* data, uint32_t size); // Initializes a PE struct from raw data
void FreePE(PE* pe); //Frees PE struct

bool Relocate(PE* pe, uintxx_t NewBase);
void BuildIAT(PE* pe);

