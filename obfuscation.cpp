#include <iostream>
#include <string>
#include <vector>
#include <iomanip>
#include <windows.h>
#include <cstdio>

// Base64 Encoding
const std::string base64_chars =
"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
"abcdefghijklmnopqrstuvwxyz"
"0123456789+/";

std::string Base64Encode(const std::vector<unsigned char>& data) {
    std::string encoded;
    unsigned char char_array_3[3], char_array_4[4];
    int i = 0;

    for (const auto& byte : data) {
        char_array_3[i++] = byte;
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) | ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) | ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for (int j = 0; j < 4; ++j)
                encoded += base64_chars[char_array_4[j]];
            i = 0;
        }
    }

    if (i) {
        for (int j = i; j < 3; ++j)
            char_array_3[j] = '\0';

        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) | ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) | ((char_array_3[2] & 0xc0) >> 6);
        char_array_4[3] = 0;

        for (int j = 0; j < i + 1; ++j)
            encoded += base64_chars[char_array_4[j]];

        while (i++ < 3)
            encoded += '=';
    }

    return encoded;
}


std::vector<unsigned char> Base64Decode(const std::string& encoded_string) {
    int in_len = encoded_string.size();
    int i = 0, in_ = 0;
    unsigned char char_array_4[4], char_array_3[3];
    std::vector<unsigned char> ret;

    auto is_base64 = [](unsigned char c) {
        return (isalnum(c) || (c == '+') || (c == '/'));
        };

    while (in_len-- && (encoded_string[in_] != '=') && is_base64(encoded_string[in_])) {
        char_array_4[i++] = encoded_string[in_]; in_++;
        if (i == 4) {
            for (i = 0; i < 4; i++)
                char_array_4[i] = base64_chars.find(char_array_4[i]);

            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

            for (i = 0; i < 3; i++)
                ret.push_back(char_array_3[i]);
            i = 0;
        }
    }

    if (i) {
        for (int j = i; j < 4; j++)
            char_array_4[j] = 0;

        for (int j = 0; j < 4; j++)
            char_array_4[j] = base64_chars.find(char_array_4[j]);

        char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
        char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
        char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

        for (int j = 0; j < i - 1; j++)
            ret.push_back(char_array_3[j]);
    }

    return ret;
}

void PrintHex(const std::vector<unsigned char>& data) {
    for (size_t i = 0; i < data.size(); ++i) {
        printf("%02X ", data[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    if (data.size() % 16 != 0) printf("\n");
}

// Format Generators
std::string GenerateUuid(const unsigned char* bytes) {
    char output[128];
    snprintf(output, sizeof(output), "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
        bytes[3], bytes[2], bytes[1], bytes[0], bytes[5], bytes[4], bytes[7], bytes[6],
        bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]);
    return std::string(output);
}

BOOL GenerateUuidOutput(const unsigned char* pShellcode, SIZE_T shellcodeSize) {
    if (!pShellcode || shellcodeSize == 0 ) {
        std::cerr << "[!] Invalid shellcode for UUID output\n";
        return FALSE;
    }

    SIZE_T paddedSize = (shellcodeSize % 16 == 0) ? shellcodeSize : ((shellcodeSize / 16) + 1) * 16;

    std::vector<unsigned char> paddedShellcode(paddedSize, 0);
    std::memcpy(paddedShellcode.data(), pShellcode, shellcodeSize);

    std::cout << "const char* UuidArray[" << shellcodeSize / 16 << "] = {\n\t";
    for (SIZE_T i = 0; i < shellcodeSize; i += 16) {
        std::string uuid = GenerateUuid(pShellcode + i);
        std::cout << "\"" << uuid << "\"" << (i + 16 < shellcodeSize ? ", " : "");
        if ((i / 16 + 1) % 3 == 0) std::cout << "\n\t";
    }
    std::cout << "\n};\n\n";
    return TRUE;
}

std::string GenerateIpv4(const unsigned char* bytes) {
    char output[32];
    snprintf(output, sizeof(output), "%d.%d.%d.%d", bytes[0], bytes[1], bytes[2], bytes[3]);
    return std::string(output);
}

BOOL GenerateIpv4Output(const unsigned char* pShellcode, SIZE_T shellcodeSize) {
    if (!pShellcode || shellcodeSize == 0 ) {
        std::cerr << "[!] Invalid shellcode for IPv4 output\n";
        return FALSE;
    }

    SIZE_T paddedSize = (shellcodeSize % 4 == 0) ? shellcodeSize : ((shellcodeSize / 4) + 1) * 4;

    std::vector<unsigned char> paddedShellcode(paddedSize, 0);
    std::memcpy(paddedShellcode.data(), pShellcode, shellcodeSize);

    std::cout << "const char* Ipv4Array[" << shellcodeSize / 4 << "] = {\n\t";
    for (SIZE_T i = 0; i < shellcodeSize; i += 4) {
        std::string ip = GenerateIpv4(pShellcode + i);
        std::cout << "\"" << ip << "\"" << (i + 4 < shellcodeSize ? ", " : "");
        if ((i / 4 + 1) % 8 == 0) std::cout << "\n\t";
    }
    std::cout << "\n};\n\n";
    return TRUE;
}

std::string GenerateIpv6(const unsigned char* bytes) {
    char output[128];
    snprintf(output, sizeof(output), "%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]);
    return std::string(output);
}

BOOL GenerateIpv6Output(const unsigned char* pShellcode, SIZE_T shellcodeSize) {
    if (!pShellcode || shellcodeSize == 0 ) {
        std::cerr << "[!] Invalid shellcode for IPv6 output\n";
        return FALSE;
    }

    SIZE_T paddedSize = (shellcodeSize % 16 == 0) ? shellcodeSize : ((shellcodeSize / 16) + 1) * 16;

    std::vector<unsigned char> paddedShellcode(paddedSize, 0);
    std::memcpy(paddedShellcode.data(), pShellcode, shellcodeSize);

    std::cout << "const char* Ipv6Array[" << shellcodeSize / 16 << "] = {\n\t";
    for (SIZE_T i = 0; i < shellcodeSize; i += 16) {
        std::string ip = GenerateIpv6(pShellcode + i);
        std::cout << "\"" << ip << "\"" << (i + 16 < shellcodeSize ? ", " : "");
        if ((i / 16 + 1) % 3 == 0) std::cout << "\n\t";
    }
    std::cout << "\n};\n\n";
    return TRUE;
}

std::string GenerateMac(const unsigned char* bytes) {
    char output[32];
    snprintf(output, sizeof(output), "%02X-%02X-%02X-%02X-%02X-%02X",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]);
    return std::string(output);
}

BOOL GenerateMacOutput(const unsigned char* pShellcode, SIZE_T shellcodeSize) {
    if (!pShellcode || shellcodeSize == 0 ) {
        std::cerr << "[!] Invalid shellcode for MAC output\n";
        return FALSE;
    }

    SIZE_T paddedSize = (shellcodeSize % 6 == 0) ? shellcodeSize : ((shellcodeSize / 6) + 1) * 6;

    std::vector<unsigned char> paddedShellcode(paddedSize, 0);
    std::memcpy(paddedShellcode.data(), pShellcode, shellcodeSize); 

    std::cout << "const char* MacArray[" << shellcodeSize / 6 << "] = {\n\t";
    for (SIZE_T i = 0; i < shellcodeSize; i += 6) {
        std::string mac = GenerateMac(pShellcode + i);
        std::cout << "\"" << mac << "\"" << (i + 6 < shellcodeSize ? ", " : "");
        if ((i / 6 + 1) % 6 == 0) std::cout << "\n\t";
    }
    std::cout << "\n};\n\n";
    return TRUE;
}

int main() {
    std::vector<unsigned char> shellcodeex = {
        0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xC0, 0x00,
        0x00, 0x00, 0x41, 0x51, 0x41, 0x50, 0x52, 0x51,
    };

    std::string encoded = Base64Encode(shellcodeex);
    std::cout << "[+] Base64 Encoded:\n" << encoded << "\n\n";

    std::vector<unsigned char> decoded = Base64Decode(encoded);
    std::cout << "[+] Decoded Shellcode:\n";
    PrintHex(decoded); 

    BYTE shellcode[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C
    };

    GenerateUuidOutput(shellcode, sizeof(shellcode));
    GenerateIpv4Output(shellcode, sizeof(shellcode));
    GenerateIpv6Output(shellcode, sizeof(shellcode));
    GenerateMacOutput(shellcode, sizeof(shellcode));

    return 0;
}
