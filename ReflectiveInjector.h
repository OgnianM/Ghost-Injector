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
#include "PE.h"

#define INJECTOR_ERR_INVALID_PROCESS -1
#define INJECTOR_ERR_FAILED_ALLOCATION -2


#define INJECTOR_VIRTUAL_IMAGE 1 // Specify if your image is already aligned to the proper virtual boundries
#define INJECTOR_FIX_PROTECT 2   // Specify if you want the protections on your virtual pages to be fixed after injection 
#define INJECTOR_BUILD_IAT 4     // Specify if you want your image's IAT to be build before injection, incompatible with INJECTOR_VIRTUAL_IMAGE
#define INJECTOR_AUTO_RUN 8      // Specify if you want your image to be ran directly after injection



/*
	hProcess	 - The target process
	hThread		 - A remote thread to use as a worker, specify INVALID_HANDLE_VALUE if you want a new one to be created.
	pe			 - The PE image to inject, make sure it's relocated and the IAT is build
	Flags		 - INJECTOR_VIRTUAL_IMAGE, INJECTOR_FIX_PROTECT, INJECTOR_RELOCATE, INJECTOR_BUILD_IAT
	Context		 - GHOSTWRITER context

	The pe will be automatically relocated to the address of the remote buffer.
*/
byte ReflectiveInject(HANDLE hProcess, HANDLE hThread, PE* pe, int Flags, PGHOSTWRITER Context);

