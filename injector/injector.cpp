#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>
#include <fstream>
#include <vector>

#pragma comment(lib, "advapi32.lib")

typedef NTSTATUS(NTAPI* pNtCreateThreadEx)(
    OUT PHANDLE hThread,
    IN ACCESS_MASK DesiredAccess,
    IN PVOID ObjectAttributes,
    IN HANDLE ProcessHandle,
    IN PVOID lpStartAddress,
    IN PVOID lpParameter,
    IN ULONG Flags,
    IN SIZE_T StackZeroBits,
    IN SIZE_T SizeOfStackCommit,
    IN SIZE_T SizeOfStackReserve,
    OUT PVOID lpBytesBuffer
    );

typedef HMODULE(WINAPI* pLoadLibraryA)(LPCSTR);
typedef FARPROC(WINAPI* pGetProcAddress)(HMODULE, LPCSTR);
typedef BOOL(WINAPI* DllMain)(HMODULE, DWORD, LPVOID);



struct MANUAL_MAPPING_DATA {
    pLoadLibraryA fnLoadLibraryA;
    pGetProcAddress fnGetProcAddress;
    LPVOID lpBase;
};

DWORD WINAPI LibraryLoader(LPVOID lpParam) {
    MANUAL_MAPPING_DATA* pData = (MANUAL_MAPPING_DATA*)lpParam;

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pData->lpBase;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)pData->lpBase + pDosHeader->e_lfanew);
    PIMAGE_OPTIONAL_HEADER pOptionalHeader = &pNtHeaders->OptionalHeader;

    pLoadLibraryA _LoadLibraryA = pData->fnLoadLibraryA;
    pGetProcAddress _GetProcAddress = pData->fnGetProcAddress;

    // Process imports
    if (pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
        PIMAGE_IMPORT_DESCRIPTOR pImportDescr = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)pData->lpBase +
            pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

        while (pImportDescr->Name) {
            char* szMod = (char*)((LPBYTE)pData->lpBase + pImportDescr->Name);
            HMODULE hDll = _LoadLibraryA(szMod);

            PIMAGE_THUNK_DATA pThunkRef = (PIMAGE_THUNK_DATA)((LPBYTE)pData->lpBase + pImportDescr->OriginalFirstThunk);
            PIMAGE_THUNK_DATA pFuncRef = (PIMAGE_THUNK_DATA)((LPBYTE)pData->lpBase + pImportDescr->FirstThunk);

            if (!pThunkRef)
                pThunkRef = pFuncRef;

            for (; pThunkRef->u1.AddressOfData; pThunkRef++, pFuncRef++) {
                if (IMAGE_SNAP_BY_ORDINAL(pThunkRef->u1.Ordinal)) {
                    pFuncRef->u1.Function = (DWORD)_GetProcAddress(hDll, (LPCSTR)IMAGE_ORDINAL(pThunkRef->u1.Ordinal));
                }
                else {
                    PIMAGE_IMPORT_BY_NAME pImport = (PIMAGE_IMPORT_BY_NAME)((LPBYTE)pData->lpBase + pThunkRef->u1.AddressOfData);
                    pFuncRef->u1.Function = (DWORD)_GetProcAddress(hDll, pImport->Name);
                }
            }
            pImportDescr++;
        }
    }

    // process relocations
    if (pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
        DWORD dwDelta = (DWORD)((LPBYTE)pData->lpBase - pOptionalHeader->ImageBase);

        PIMAGE_BASE_RELOCATION pRelocData = (PIMAGE_BASE_RELOCATION)((LPBYTE)pData->lpBase +
            pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

        while (pRelocData->VirtualAddress) {
            UINT AmountOfEntries = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            WORD* pRelativeInfo = (WORD*)(pRelocData + 1);

            for (UINT i = 0; i < AmountOfEntries; i++, pRelativeInfo++) {
                if ((*pRelativeInfo >> 12) == IMAGE_REL_BASED_HIGHLOW) {
                    DWORD* pPatch = (DWORD*)((LPBYTE)pData->lpBase + pRelocData->VirtualAddress + (*pRelativeInfo & 0xFFF));
                    *pPatch += dwDelta;
                }
            }
            pRelocData = (PIMAGE_BASE_RELOCATION)((LPBYTE)pRelocData + pRelocData->SizeOfBlock);
        }
    }

    // call DllMain
    DllMain pDllMain = (DllMain)((LPBYTE)pData->lpBase + pOptionalHeader->AddressOfEntryPoint);
    pDllMain((HMODULE)pData->lpBase, DLL_PROCESS_ATTACH, NULL);

    return 0;
}

bool ManualMap(HANDLE hProcess, const char* dllPath) {
    // read DLL file
    std::ifstream file(dllPath, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        std::cout << "[!] could not open DLL (make sure the path is correct)!" << std::endl;
        return false;
    }

    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<BYTE> buffer(size);
    if (!file.read((char*)buffer.data(), size)) {
        std::cout << "[!] could not read DLL!" << std::endl;
        return false;
    }
    file.close();

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)buffer.data();
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        std::cout << "[!] invalid DLL!" << std::endl;
        return false;
    }

    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(buffer.data() + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        std::cout << "[!] invalid NT Headers!" << std::endl;
        return false;
    }

    // allocate memory in target process
    LPVOID lpTargetBase = VirtualAllocEx(hProcess, NULL, pNtHeaders->OptionalHeader.SizeOfImage,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (!lpTargetBase) {
        std::cout << "[!] memory allocation failed: " << GetLastError() << std::endl;
        return false;
    }

    std::cout << "[+] memory allocated at: 0x" << std::hex << lpTargetBase << std::dec << std::endl;

    // copy headers
    if (!WriteProcessMemory(hProcess, lpTargetBase, buffer.data(), pNtHeaders->OptionalHeader.SizeOfHeaders, NULL)) {
        std::cout << "[!] headers writing failed!" << std::endl;
        VirtualFreeEx(hProcess, lpTargetBase, 0, MEM_RELEASE);
        return false;
    }

    // copy sections
    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
    for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++, pSectionHeader++) {
        if (!WriteProcessMemory(hProcess,
            (LPBYTE)lpTargetBase + pSectionHeader->VirtualAddress,
            buffer.data() + pSectionHeader->PointerToRawData,
            pSectionHeader->SizeOfRawData, NULL)) {
            std::cout << "[!] writing section failed!" << std::endl;
            VirtualFreeEx(hProcess, lpTargetBase, 0, MEM_RELEASE);
            return false;
        }
    }

    std::cout << "[+] sections -> success!" << std::endl;

    // prepare loader data
    MANUAL_MAPPING_DATA data;
    data.fnLoadLibraryA = LoadLibraryA;
    data.fnGetProcAddress = GetProcAddress;
    data.lpBase = lpTargetBase;

    LPVOID lpDataRemote = VirtualAllocEx(hProcess, NULL, sizeof(MANUAL_MAPPING_DATA),
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!lpDataRemote) {
        std::cout << "[!] lpDataRemote -> VirtualAllocEx failed!" << std::endl;
        VirtualFreeEx(hProcess, lpTargetBase, 0, MEM_RELEASE);
        return false;
    }

    WriteProcessMemory(hProcess, lpDataRemote, &data, sizeof(MANUAL_MAPPING_DATA), NULL);

    // write loader stub
    LPVOID lpLoaderRemote = VirtualAllocEx(hProcess, NULL, 4096,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (!lpLoaderRemote) {
        std::cout << "[!] lpLoaderRemote->VirtualAllocEx failed!" << std::endl;
        VirtualFreeEx(hProcess, lpTargetBase, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, lpDataRemote, 0, MEM_RELEASE);
        return false;
    }

    WriteProcessMemory(hProcess, lpLoaderRemote, LibraryLoader, 4096, NULL);


	// execute loader via NtCreateThreadEx
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    pNtCreateThreadEx NtCreateThreadEx = reinterpret_cast<pNtCreateThreadEx>(GetProcAddress(hNtdll, "NtCreateThreadEx"));

    if (!NtCreateThreadEx) {
        std::cerr << "[-] could not find NtCreateThreadEx" << std::endl;
        VirtualFreeEx(hProcess, lpTargetBase, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, lpDataRemote, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, lpLoaderRemote, 0, MEM_RELEASE);
        return false;
    }
    HANDLE hThread = nullptr;
    NTSTATUS status = NtCreateThreadEx(
        &hThread,
        THREAD_ALL_ACCESS,
        nullptr,
        hProcess,
        lpLoaderRemote,
        lpDataRemote,
        0,
        0,
        0,
        0,
        nullptr
    );

    if (status != 0 || !hThread) {
        std::cerr << "[-] NtCreateThreadEx failed: 0x" << std::hex << status << std::dec << std::endl;
        VirtualFreeEx(hProcess, lpTargetBase, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, lpDataRemote, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, lpLoaderRemote, 0, MEM_RELEASE);
        return false;
    }

    std::cout << "[+] NtCreateThreadEx success!" << std::endl;

    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);

    // cleanup
    VirtualFreeEx(hProcess, lpDataRemote, 0, MEM_RELEASE);
    VirtualFreeEx(hProcess, lpLoaderRemote, 0, MEM_RELEASE);

    std::cout << "[+] success!" << std::endl;
    return true;
}

int main(int argc, char* argv[]) {
    std::cout << "=== Manual Map Injector x86 ===" << std::endl;
    std::cout << "Usage: injector.exe <PID> <DLL_path>" << std::endl << std::endl;

    if (argc < 3) {
        std::cout << "[!] insufficient params!" << std::endl;
        return 1;
    }

    const char* pidChar = argv[1];
    const char* dllPath = argv[2];

    std::cout << "[*] DLL Path: " << dllPath << std::endl << std::endl;

	DWORD pid = atoi(pidChar);

	std::cout << "[*] PID: " << pid << std::endl;

    Sleep(500); // wait for process initialization

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        std::cout << "[!] OpenProcess failed: " << GetLastError() << std::endl;
        return 1;
    }

    std::cout << "[+] OpenProcess succes!" << std::endl << std::endl;

    // perform manual mapping
    bool success = ManualMap(hProcess, dllPath);

    CloseHandle(hProcess);

    if (success) {
        std::cout << "\n[+] successfully injected!" << std::endl;
    }
    else {
        std::cout << "\n[!] injection failed!" << std::endl;
    }

    return success ? 0 : 1;
}