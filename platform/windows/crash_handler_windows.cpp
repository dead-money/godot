/**************************************************************************/
/*  crash_handler_windows.cpp                                             */
/**************************************************************************/
/*                         This file is part of:                          */
/*                             GODOT ENGINE                               */
/*                        https://godotengine.org                         */
/**************************************************************************/
/* Copyright (c) 2014-present Godot Engine contributors (see AUTHORS.md). */
/* Copyright (c) 2007-2014 Juan Linietsky, Ariel Manzur.                  */
/*                                                                        */
/* Permission is hereby granted, free of charge, to any person obtaining  */
/* a copy of this software and associated documentation files (the        */
/* "Software"), to deal in the Software without restriction, including    */
/* without limitation the rights to use, copy, modify, merge, publish,    */
/* distribute, sublicense, and/or sell copies of the Software, and to     */
/* permit persons to whom the Software is furnished to do so, subject to  */
/* the following conditions:                                              */
/*                                                                        */
/* The above copyright notice and this permission notice shall be         */
/* included in all copies or substantial portions of the Software.        */
/*                                                                        */
/* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,        */
/* EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF     */
/* MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. */
/* IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY   */
/* CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,   */
/* TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE      */
/* SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.                 */
/**************************************************************************/

#include "crash_handler_windows.h"

#include <string.h>

// CoreCLR terminates the process itself when a hardware fault unwinds into
// managed frames, before the unhandled exception filter ever runs, so a crash
// reporter installed with SetUnhandledExceptionFilter never sees engine faults
// reached from C#. Vectored handlers run before that, so this one hands such
// faults to the reporter directly. Faults in managed code and in the runtime's
// own modules are left alone; the runtime turns those into managed exceptions.

static LPTOP_LEVEL_EXCEPTION_FILTER baseline_filter = nullptr;
static LPTOP_LEVEL_EXCEPTION_FILTER reporter_filter = nullptr;

static LPTOP_LEVEL_EXCEPTION_FILTER current_filter() {
	LPTOP_LEVEL_EXCEPTION_FILTER filter = SetUnhandledExceptionFilter(nullptr);
	SetUnhandledExceptionFilter(filter);
	return filter;
}

static bool is_hardware_fault(DWORD p_code) {
	switch (p_code) {
		case EXCEPTION_ACCESS_VIOLATION:
		case EXCEPTION_IN_PAGE_ERROR:
		case EXCEPTION_ILLEGAL_INSTRUCTION:
		case EXCEPTION_PRIV_INSTRUCTION:
		case EXCEPTION_INT_DIVIDE_BY_ZERO:
		case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
			return true;
		default:
			return false;
	}
}

// Nothing here may take the loader lock: the faulting thread might hold it.
static bool is_native_module_address(const void *p_address) {
	MEMORY_BASIC_INFORMATION info;
	if (VirtualQuery(p_address, &info, sizeof(info)) != sizeof(info) || info.Type != MEM_IMAGE) {
		return false;
	}
	const BYTE *base = (const BYTE *)info.AllocationBase;
	const IMAGE_DOS_HEADER *dos = (const IMAGE_DOS_HEADER *)base;
	if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
		return false;
	}
	const IMAGE_NT_HEADERS *nt = (const IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
	if (nt->Signature != IMAGE_NT_SIGNATURE) {
		return false;
	}
	const IMAGE_DATA_DIRECTORY *directories = nt->OptionalHeader.DataDirectory;
	DWORD directory_count = nt->OptionalHeader.NumberOfRvaAndSizes;
	if (directory_count > IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR && directories[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].Size != 0) {
		return false; // Managed assembly, including ReadyToRun images.
	}
	if (directory_count > IMAGE_DIRECTORY_ENTRY_EXPORT && directories[IMAGE_DIRECTORY_ENTRY_EXPORT].Size != 0) {
		const IMAGE_EXPORT_DIRECTORY *exports = (const IMAGE_EXPORT_DIRECTORY *)(base + directories[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
		const char *name = (const char *)(base + exports->Name);
		if (_stricmp(name, "coreclr.dll") == 0 || _stricmp(name, "clrjit.dll") == 0 || _strnicmp(name, "clrgc", 5) == 0) {
			return false;
		}
	}
	return true;
}

static LONG WINAPI forward_native_fault(EXCEPTION_POINTERS *p_exception) {
	if (!is_hardware_fault(p_exception->ExceptionRecord->ExceptionCode) || IsDebuggerPresent()) {
		return EXCEPTION_CONTINUE_SEARCH;
	}
	if (!is_native_module_address(p_exception->ExceptionRecord->ExceptionAddress)) {
		return EXCEPTION_CONTINUE_SEARCH;
	}
	LPTOP_LEVEL_EXCEPTION_FILTER filter = current_filter();
	if (filter != nullptr && !is_native_module_address((const void *)filter)) {
		filter = reporter_filter; // The managed runtime took over; use what it replaced.
	}
	if (filter == nullptr || filter == baseline_filter) {
		return EXCEPTION_CONTINUE_SEARCH;
	}
	filter(p_exception); // A crash reporter writes its dump and terminates the process here.
	return EXCEPTION_CONTINUE_SEARCH;
}

void CrashHandler::remember_crash_reporter() {
	reporter_filter = current_filter();
}

void CrashHandler::install_native_fault_forwarder() {
	if (native_fault_forwarder != nullptr) {
		return;
	}
	baseline_filter = current_filter();
	native_fault_forwarder = AddVectoredExceptionHandler(1, forward_native_fault);
}

void CrashHandler::remove_native_fault_forwarder() {
	if (native_fault_forwarder != nullptr) {
		RemoveVectoredExceptionHandler(native_fault_forwarder);
		native_fault_forwarder = nullptr;
	}
}
