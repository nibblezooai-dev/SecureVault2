// SecureVault2 compile command: cl /MT /O2 /GS /sdl main.cpp bcrypt.lib advapi32.lib user32.lib gdi32.lib comdlg32.lib shell32.lib /Fe:SecureVault2.exe /link /NXCOMPAT /DYNAMICBASE /SUBSYSTEM:WINDOWS

#define VAULT_VERSION "v1.0-beta"

#include <windows.h>
#include <bcrypt.h>
#include <string>
#include <vector>
#include <stdio.h>
#include <shellapi.h>
#include <shlobj.h>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "comdlg32.lib")
#pragma comment(lib, "shell32.lib")

// ==========================================
// STRUCTS AND CONSTANTS
// ==========================================
#pragma pack(push, 1)
struct VaultHeader {
    char magic[4]; // 'S', 'V', 'L', '2'
    uint8_t version; // 1
    BYTE salt[32];
    uint32_t iterations; // 500000
    uint32_t fileCount;
    uint8_t failedAttempts;
    uint64_t lastFailTime;
    uint64_t dataOffset;
    uint64_t entriesOffset;
    BYTE vaultAuthTag[32];
    BYTE pwdVerifyTag[32];
    BYTE pwdVerifyIV[12];
    BYTE reserved[78];
    BYTE headerHMAC[32];
};

struct FileEntry {
    BYTE encryptedName[256];
    uint32_t nameLen;
    uint64_t originalSize;
    uint64_t storedSize;
    uint64_t dataOffset;
    BYTE fileIV[12];
    BYTE nameAuthTag[16];
    BYTE reserved[200];
};
#pragma pack(pop)

// ==========================================
// FORWARD DECLARATIONS
// ==========================================
void wipeSensitiveData(const void* ptr, size_t size);
void SetStatus(const char* msg);
void CenterWindow(HWND hwnd, HWND hParent);
std::string getPasswordViaKeyboard(HWND hParent, const char* title);
LRESULT CALLBACK KeyboardProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
LRESULT CALLBACK ProgressProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
LRESULT CALLBACK InputBoxProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
LRESULT CALLBACK ResultBoxProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);

bool constTimeEqual(const BYTE* a, const BYTE* b, size_t len);
std::string formatSize(uint64_t bytes);
void cleanupTempFiles();

void computeVaultHMAC(HANDLE hVault, uint64_t entriesOffset, const BYTE* authKey, BYTE* outTag);
bool verifyVaultHMAC(HANDLE hVault, const VaultHeader& header, const BYTE* authKey);
void computeHeaderHMAC(const VaultHeader& header, BYTE* outHMAC);
bool verifyHeaderHMAC(const VaultHeader& header);

bool validateVault(HANDLE hVault, VaultHeader& header, uint64_t& fileSize);
bool isValidEntry(const FileEntry& e, uint64_t fileSize);
bool deriveKey(const std::string& password, const BYTE* salt, BYTE* outEncKey, BYTE* outAuthKey);
void encryptName(const std::string& name, const BYTE* encKey, const BYTE* authKey, BYTE* outEncrypted, uint32_t& outNameLen, BYTE* outIV, BYTE* outAuthTag);
bool decryptName(const BYTE* encryptedName, uint32_t nameLen, const BYTE* encKey, const BYTE* authKey, const BYTE* iv, const BYTE* authTag, std::string& outName);
bool encryptFile(HANDLE hIn, HANDLE hOutVault, const BYTE* encKey, const BYTE* authKey, FileEntry& entry);
bool decryptFile(const FileEntry& entry, HANDLE hVault, const std::string& outPath, const BYTE* encKey, const BYTE* authKey);
bool verifyEntry(HANDLE hVault, const FileEntry& entry, const BYTE* encKey, const BYTE* authKey);
bool validatePassword(const std::string& pwd, std::string& errorMsg);
bool verifyPassword(HANDLE hVault, const VaultHeader& header, const std::string& pwd, BYTE* outEncKey, BYTE* outAuthKey);
bool guiAuthenticate(HWND hParent, HANDLE hVault, VaultHeader& header, BYTE* outEncKey, BYTE* outAuthKey);

void CreateVaultFlow();
void LockFileFlow();
void UnlockFileFlow();
void ListVerifyFlow();

static const DWORD CHUNK_SIZE = 65536;

// ==========================================
// GLOBALS FOR GUI
// ==========================================
HINSTANCE g_hInst = NULL;
HWND g_hMainWnd = NULL;
HWND g_hProgressWnd = NULL;
char g_StatusText[256] = "Ready";
std::string g_InputBoxText;
std::string g_ListResultText;
HFONT g_hFontTitle = NULL, g_hFontSub = NULL, g_hFontBtn = NULL, g_hFontMono = NULL, g_hFontStatus = NULL;

// ==========================================
// UTILITY FUNCTIONS
// ==========================================
bool constTimeEqual(const BYTE* a, const BYTE* b, size_t len) {
    volatile BYTE acc = 0;
    for (size_t i = 0; i < len; ++i) {
        acc |= (a[i] ^ b[i]);
    }
    return acc == 0;
}

void wipeSensitiveData(const void* ptr, size_t size) {
    if (!ptr || size == 0) return;
    SecureZeroMemory((PVOID)ptr, size);
    (void)BCryptGenRandom(NULL, (PUCHAR)(void*)ptr, (ULONG)size, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
}

std::string formatSize(uint64_t bytes) {
    char buf[64];
    if (bytes >= 1024ULL * 1024ULL * 1024ULL) snprintf(buf, sizeof(buf), "%.2f GB", (double)bytes / (1024.0 * 1024.0 * 1024.0));
    else if (bytes >= 1024ULL * 1024ULL) snprintf(buf, sizeof(buf), "%.2f MB", (double)bytes / (1024.0 * 1024.0));
    else snprintf(buf, sizeof(buf), "%.2f KB", (double)bytes / 1024.0);
    return std::string(buf);
}

void cleanupTempFiles() {
    char tempPath[MAX_PATH];
    GetTempPathA(MAX_PATH, tempPath);
    std::string searchPath = std::string(tempPath) + "SVL*.tmp";
    
    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA(searchPath.c_str(), &fd);
    if (hFind != INVALID_HANDLE_VALUE) {
        FILETIME ftNow;
        GetSystemTimeAsFileTime(&ftNow);
        ULARGE_INTEGER now;
        now.LowPart = ftNow.dwLowDateTime;
        now.HighPart = ftNow.dwHighDateTime;
        
        do {
            ULARGE_INTEGER fileTime;
            fileTime.LowPart = fd.ftCreationTime.dwLowDateTime;
            fileTime.HighPart = fd.ftCreationTime.dwHighDateTime;
            
            if (now.QuadPart > fileTime.QuadPart && (now.QuadPart - fileTime.QuadPart) > 36000000000ULL) {
                std::string fullPath = std::string(tempPath) + fd.cFileName;
                (void)DeleteFileA(fullPath.c_str());
            }
        } while (FindNextFileA(hFind, &fd));
        FindClose(hFind);
    }
}

// ==========================================
// VAULT HMACS
// ==========================================
void computeVaultHMAC(HANDLE hVault, uint64_t entriesOffset, const BYTE* authKey, BYTE* outTag) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    if ((LONG)BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG) != 0x00000000L) return;

    if ((LONG)BCryptCreateHash(hAlg, &hHash, NULL, 0, (PUCHAR)authKey, (ULONG)32, 0) == 0x00000000L) {
        LARGE_INTEGER liPos; liPos.QuadPart = (LONGLONG)entriesOffset;
        SetFilePointerEx(hVault, liPos, NULL, FILE_BEGIN);
        
        static BYTE buffer[CHUNK_SIZE];
        DWORD br;
        while (ReadFile(hVault, buffer, (DWORD)CHUNK_SIZE, &br, NULL) && br > 0) {
            (void)BCryptHashData(hHash, (PUCHAR)buffer, (ULONG)br, 0);
        }
        
        (void)BCryptFinishHash(hHash, (PUCHAR)outTag, (ULONG)32, 0);
        (void)BCryptDestroyHash(hHash);
    }
    (void)BCryptCloseAlgorithmProvider(hAlg, 0);
}

bool verifyVaultHMAC(HANDLE hVault, const VaultHeader& header, const BYTE* authKey) {
    BYTE expected[32];
    computeVaultHMAC(hVault, header.entriesOffset, authKey, expected);
    return constTimeEqual(expected, header.vaultAuthTag, 32);
}

void computeHeaderHMAC(const VaultHeader& header, BYTE* outHMAC) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    if ((LONG)BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG) != 0x00000000L) return;
    
    BYTE hmacKey[16] = "SVL2_HEADER_KEY";
    if ((LONG)BCryptCreateHash(hAlg, &hHash, NULL, 0, (PUCHAR)hmacKey, (ULONG)15, 0) == 0x00000000L) {
        (void)BCryptHashData(hHash, (PUCHAR)&header, (ULONG)(sizeof(VaultHeader) - 32), 0);
        (void)BCryptFinishHash(hHash, (PUCHAR)outHMAC, (ULONG)32, 0);
        (void)BCryptDestroyHash(hHash);
    }
    (void)BCryptCloseAlgorithmProvider(hAlg, 0);
}

bool verifyHeaderHMAC(const VaultHeader& header) {
    BYTE expected[32];
    computeHeaderHMAC(header, expected);
    return constTimeEqual(expected, header.headerHMAC, 32);
}

// ==========================================
// VAULT VALIDATION
// ==========================================
bool validateVault(HANDLE hVault, VaultHeader& header, uint64_t& fileSize) {
    LARGE_INTEGER sz;
    if (!GetFileSizeEx(hVault, &sz)) return false;
    fileSize = (uint64_t)sz.QuadPart;

    DWORD br;
    LARGE_INTEGER liPos; liPos.QuadPart = 0; SetFilePointerEx(hVault, liPos, NULL, FILE_BEGIN);
    if (!ReadFile(hVault, &header, sizeof(header), &br, NULL) || br != sizeof(header)) return false;

    if (!constTimeEqual((const BYTE*)header.magic, (const BYTE*)"SVL2", 4)) return false;
    if (header.version != 1) return false;
    if (!verifyHeaderHMAC(header)) {
        MessageBoxA(NULL, "Header integrity check failed", "Error", MB_ICONERROR);
        return false;
    }
    if (header.fileCount > 100000) return false;
    if (header.entriesOffset > fileSize) return false;
    if (header.dataOffset > fileSize) return false;
    return true;
}

bool isValidEntry(const FileEntry& e, uint64_t fileSize) {
    if (e.storedSize == 0) return false;
    if (e.originalSize == 0) return false;
    if (e.dataOffset + e.storedSize > fileSize) return false;
    if (e.nameLen == 0 || e.nameLen >= 256) return false;
    return true;
}

// ==========================================
// KEY DERIVATION
// ==========================================
bool deriveKey(const std::string& password, const BYTE* salt, BYTE* outEncKey, BYTE* outAuthKey) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    if ((LONG)BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA512_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG) != 0x00000000L) return false;
    
    std::string pwdEnc = password + "ENCRYPT";
    std::string pwdAuth = password + "AUTH";
    
    bool s1 = ((LONG)BCryptDeriveKeyPBKDF2(hAlg, (PUCHAR)pwdEnc.data(), (ULONG)pwdEnc.length(), (PUCHAR)salt, (ULONG)32, (ULONGLONG)500000, (PUCHAR)outEncKey, (ULONG)32, 0) == 0x00000000L);
    bool s2 = ((LONG)BCryptDeriveKeyPBKDF2(hAlg, (PUCHAR)pwdAuth.data(), (ULONG)pwdAuth.length(), (PUCHAR)salt, (ULONG)32, (ULONGLONG)500000, (PUCHAR)outAuthKey, (ULONG)32, 0) == 0x00000000L);
    
    (void)BCryptCloseAlgorithmProvider(hAlg, 0);
    wipeSensitiveData(pwdEnc.data(), pwdEnc.length());
    wipeSensitiveData(pwdAuth.data(), pwdAuth.length());

    if (!s1 || !s2) {
        wipeSensitiveData(outEncKey, 32);
        wipeSensitiveData(outAuthKey, 32);
    }
    return s1 && s2;
}

// ==========================================
// CRYPTO ENGINE
// ==========================================
void encryptName(const std::string& name, const BYTE* encKey, const BYTE* authKey, BYTE* outEncrypted, uint32_t& outNameLen, BYTE* outIV, BYTE* outAuthTag) {
    outNameLen = (uint32_t)name.length();
    BCRYPT_ALG_HANDLE hAlg = NULL; 
    BCRYPT_KEY_HANDLE hKey = NULL;
    
    BYTE inBuf[256] = {0};
    memcpy(inBuf, name.c_str(), name.length());

    if ((LONG)BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0) != 0x00000000L) {
        wipeSensitiveData(inBuf, 256);
        return;
    }

    (void)BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM, (ULONG)sizeof(L"ChainingModeGCM"), 0);
    (void)BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, (PUCHAR)encKey, (ULONG)32, 0);
    (void)BCryptGenRandom(NULL, (PUCHAR)outIV, (ULONG)12, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = (PUCHAR)outIV;
    authInfo.cbNonce = (ULONG)12;
    authInfo.pbTag = (PUCHAR)outAuthTag;
    authInfo.cbTag = (ULONG)16;
    authInfo.pbAuthData = (PUCHAR)authKey;
    authInfo.cbAuthData = (ULONG)32;

    ULONG outBytes = 0;
    
    (void)BCryptEncrypt(hKey, (PUCHAR)inBuf, (ULONG)outNameLen, &authInfo, NULL, 0, (PUCHAR)outEncrypted, (ULONG)256, &outBytes, 0);
    outNameLen = (uint32_t)outBytes;

    (void)BCryptDestroyKey(hKey);
    (void)BCryptCloseAlgorithmProvider(hAlg, 0);
    wipeSensitiveData(inBuf, 256);
}

bool decryptName(const BYTE* encryptedName, uint32_t nameLen, const BYTE* encKey, const BYTE* authKey, const BYTE* iv, const BYTE* authTag, std::string& outName) {
    BCRYPT_ALG_HANDLE hAlg = NULL; 
    BCRYPT_KEY_HANDLE hKey = NULL;
    
    if ((LONG)BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0) != 0x00000000L) return false;
    (void)BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM, (ULONG)sizeof(L"ChainingModeGCM"), 0);
    (void)BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, (PUCHAR)encKey, (ULONG)32, 0);
    
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = (PUCHAR)iv;
    authInfo.cbNonce = (ULONG)12;
    authInfo.pbTag = (PUCHAR)authTag;
    authInfo.cbTag = (ULONG)16;
    authInfo.pbAuthData = (PUCHAR)authKey;
    authInfo.cbAuthData = (ULONG)32;

    ULONG outBytes = 0;
    BYTE outBuf[256] = {0};
    LONG status = (LONG)BCryptDecrypt(hKey, (PUCHAR)encryptedName, (ULONG)nameLen, &authInfo, NULL, 0, (PUCHAR)outBuf, (ULONG)256, &outBytes, 0);
    
    (void)BCryptDestroyKey(hKey);
    (void)BCryptCloseAlgorithmProvider(hAlg, 0);
    
    if (status != 0x00000000L) {
        wipeSensitiveData(outBuf, 256);
        return false;
    }
    outName = std::string((char*)outBuf, (size_t)outBytes);
    wipeSensitiveData(outBuf, 256);
    return true;
}

// ==========================================
// FILE ENCRYPTION
// ==========================================
bool encryptFile(HANDLE hIn, HANDLE hOutVault, const BYTE* encKey, const BYTE* authKey, FileEntry& entry) {
    BCRYPT_ALG_HANDLE hAlg = NULL; 
    BCRYPT_KEY_HANDLE hKey = NULL;
    
    if ((LONG)BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0) != 0x00000000L) return false;
    (void)BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM, (ULONG)sizeof(L"ChainingModeGCM"), 0);
    (void)BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, (PUCHAR)encKey, (ULONG)32, 0);

    (void)BCryptGenRandom(NULL, (PUCHAR)entry.fileIV, (ULONG)12, BCRYPT_USE_SYSTEM_PREFERRED_RNG);

    static BYTE inBuffer[CHUNK_SIZE];
    static BYTE outBuffer[CHUNK_SIZE];
    uint64_t totalRead = 0;
    uint32_t chunkIndex = 0;
    bool success = true;

    while (totalRead < entry.originalSize) {
        DWORD toRead = (DWORD)( ((entry.originalSize - totalRead) > (uint64_t)CHUNK_SIZE) ? (uint64_t)CHUNK_SIZE : (entry.originalSize - totalRead) );
        DWORD bytesRead = 0;
        if (!ReadFile(hIn, inBuffer, toRead, &bytesRead, NULL) || bytesRead == 0) {
            success = false; break;
        }
        totalRead += (uint64_t)bytesRead;

        BYTE chunkIV[12];
        memcpy(chunkIV, entry.fileIV, 12);
        uint32_t* counter = (uint32_t*)(chunkIV + 8);
        *counter = *counter + chunkIndex;
        chunkIndex++;

        BYTE authTag[16];
        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
        BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
        authInfo.pbNonce = (PUCHAR)chunkIV;
        authInfo.cbNonce = (ULONG)12;
        authInfo.pbTag = (PUCHAR)authTag;
        authInfo.cbTag = (ULONG)16;
        authInfo.pbAuthData = (PUCHAR)authKey;
        authInfo.cbAuthData = (ULONG)32;

        ULONG outBytes = 0;
        LONG status = (LONG)BCryptEncrypt(hKey, (PUCHAR)inBuffer, (ULONG)bytesRead, &authInfo, NULL, 0, (PUCHAR)outBuffer, (ULONG)CHUNK_SIZE, &outBytes, 0);
        if (status != 0x00000000L) {
            success = false; break;
        }

        DWORD written = 0;
        if (!WriteFile(hOutVault, outBuffer, (DWORD)outBytes, &written, NULL) || written != (DWORD)outBytes) {
            success = false; break;
        }
        if (!WriteFile(hOutVault, authTag, 16, &written, NULL) || written != 16) {
            success = false; break;
        }

        entry.storedSize += (uint64_t)outBytes + 16ULL;
        
        if (g_hProgressWnd) {
            int pct = entry.originalSize ? (int)((totalRead * 100ULL) / entry.originalSize) : 0;
            PostMessageA(g_hProgressWnd, WM_APP + 1, (WPARAM)pct, 0);
            MSG msg;
            while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
                TranslateMessage(&msg);
                DispatchMessage(&msg);
            }
        }
        wipeSensitiveData(inBuffer, CHUNK_SIZE);
        wipeSensitiveData(outBuffer, CHUNK_SIZE);
    }

    (void)BCryptDestroyKey(hKey);
    (void)BCryptCloseAlgorithmProvider(hAlg, 0);
    wipeSensitiveData(inBuffer, CHUNK_SIZE);
    wipeSensitiveData(outBuffer, CHUNK_SIZE);
    return success;
}

// ==========================================
// FILE DECRYPTION
// ==========================================
bool decryptFile(const FileEntry& entry, HANDLE hVault, const std::string& outPath, const BYTE* encKey, const BYTE* authKey) {
    HANDLE hOut = CreateFileA(outPath.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hOut == INVALID_HANDLE_VALUE) return false;

    LARGE_INTEGER liPos; liPos.QuadPart = (LONGLONG)entry.dataOffset; SetFilePointerEx(hVault, liPos, NULL, FILE_BEGIN);

    BCRYPT_ALG_HANDLE hAlg = NULL; 
    BCRYPT_KEY_HANDLE hKey = NULL;
    
    if ((LONG)BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0) != 0x00000000L) {
        CloseHandle(hOut); (void)DeleteFileA(outPath.c_str()); return false;
    }
    (void)BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM, (ULONG)sizeof(L"ChainingModeGCM"), 0);
    (void)BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, (PUCHAR)encKey, (ULONG)32, 0);

    static BYTE inBuffer[CHUNK_SIZE + 16];
    static BYTE outBuffer[CHUNK_SIZE];
    uint64_t totalRead = 0;
    uint32_t chunkIndex = 0;
    bool success = true;

    while (totalRead < entry.storedSize) {
        uint64_t plainRemaining = entry.originalSize - ((uint64_t)chunkIndex * (uint64_t)CHUNK_SIZE);
        DWORD plainChunkSize = (DWORD)( (plainRemaining > (uint64_t)CHUNK_SIZE) ? (uint64_t)CHUNK_SIZE : plainRemaining );
        DWORD cipherChunkSize = plainChunkSize + 16;
        
        DWORD bytesRead = 0;
        if (!ReadFile(hVault, inBuffer, cipherChunkSize, &bytesRead, NULL) || bytesRead != cipherChunkSize) {
            success = false; break;
        }
        totalRead += (uint64_t)bytesRead;

        BYTE chunkIV[12];
        memcpy(chunkIV, entry.fileIV, 12);
        uint32_t* counter = (uint32_t*)(chunkIV + 8);
        *counter = *counter + chunkIndex;
        chunkIndex++;

        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
        BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
        authInfo.pbNonce = (PUCHAR)chunkIV;
        authInfo.cbNonce = (ULONG)12;
        authInfo.pbTag = (PUCHAR)(inBuffer + plainChunkSize);
        authInfo.cbTag = (ULONG)16;
        authInfo.pbAuthData = (PUCHAR)authKey;
        authInfo.cbAuthData = (ULONG)32;

        ULONG outBytes = 0;
        LONG status = (LONG)BCryptDecrypt(hKey, (PUCHAR)inBuffer, (ULONG)plainChunkSize, &authInfo, NULL, 0, (PUCHAR)outBuffer, (ULONG)CHUNK_SIZE, &outBytes, 0);
        if (status != 0x00000000L) {
            success = false; break;
        }

        DWORD written = 0;
        if (plainChunkSize > 0) {
            if (!WriteFile(hOut, outBuffer, (DWORD)outBytes, &written, NULL) || written != (DWORD)outBytes) {
                success = false; break;
            }
        }
        
        MSG msg;
        while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) { TranslateMessage(&msg); DispatchMessage(&msg); }
    }

    (void)BCryptDestroyKey(hKey);
    (void)BCryptCloseAlgorithmProvider(hAlg, 0);
    CloseHandle(hOut);

    wipeSensitiveData(inBuffer, CHUNK_SIZE + 16);
    wipeSensitiveData(outBuffer, CHUNK_SIZE);

    if (!success) (void)DeleteFileA(outPath.c_str());
    return success;
}

bool verifyEntry(HANDLE hVault, const FileEntry& entry, const BYTE* encKey, const BYTE* authKey) {
    LARGE_INTEGER liPos; liPos.QuadPart = (LONGLONG)entry.dataOffset; SetFilePointerEx(hVault, liPos, NULL, FILE_BEGIN);
    
    BCRYPT_ALG_HANDLE hAlg = NULL; 
    BCRYPT_KEY_HANDLE hKey = NULL;
    
    if ((LONG)BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0) != 0x00000000L) return false;
    (void)BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM, (ULONG)sizeof(L"ChainingModeGCM"), 0);
    (void)BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, (PUCHAR)encKey, (ULONG)32, 0);

    static BYTE inBuffer[CHUNK_SIZE + 16];
    static BYTE outBuffer[CHUNK_SIZE];
    uint64_t totalRead = 0;
    uint32_t chunkIndex = 0;
    bool success = true;

    while (totalRead < entry.storedSize) {
        uint64_t plainRemaining = entry.originalSize - ((uint64_t)chunkIndex * (uint64_t)CHUNK_SIZE);
        DWORD plainChunkSize = (DWORD)( (plainRemaining > (uint64_t)CHUNK_SIZE) ? (uint64_t)CHUNK_SIZE : plainRemaining );
        DWORD cipherChunkSize = plainChunkSize + 16;
        
        DWORD bytesRead = 0;
        if (!ReadFile(hVault, inBuffer, cipherChunkSize, &bytesRead, NULL) || bytesRead != cipherChunkSize) {
            success = false; break;
        }
        totalRead += (uint64_t)bytesRead;

        BYTE chunkIV[12];
        memcpy(chunkIV, entry.fileIV, 12);
        uint32_t* counter = (uint32_t*)(chunkIV + 8);
        *counter = *counter + chunkIndex;
        chunkIndex++;

        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
        BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
        authInfo.pbNonce = (PUCHAR)chunkIV;
        authInfo.cbNonce = (ULONG)12;
        authInfo.pbTag = (PUCHAR)(inBuffer + plainChunkSize);
        authInfo.cbTag = (ULONG)16;
        authInfo.pbAuthData = (PUCHAR)authKey;
        authInfo.cbAuthData = (ULONG)32;

        ULONG outBytes = 0;
        LONG status = (LONG)BCryptDecrypt(hKey, (PUCHAR)inBuffer, (ULONG)plainChunkSize, &authInfo, NULL, 0, (PUCHAR)outBuffer, (ULONG)CHUNK_SIZE, &outBytes, 0);
        if (status != 0x00000000L) {
            success = false; break;
        }
        
        MSG msg;
        while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) { TranslateMessage(&msg); DispatchMessage(&msg); }
    }

    (void)BCryptDestroyKey(hKey);
    (void)BCryptCloseAlgorithmProvider(hAlg, 0);
    wipeSensitiveData(inBuffer, CHUNK_SIZE + 16);
    wipeSensitiveData(outBuffer, CHUNK_SIZE);
    return success;
}

// ==========================================
// PASSWORD HANDLING
// ==========================================
bool validatePassword(const std::string& pwd, std::string& errorMsg) {
    if (pwd.length() < 12) { errorMsg = "Must be at least 12 characters."; return false; }
    bool up = false, low = false, dig = false, sym = false;
    std::string symbols = "!@#$%^&*()";
    for (char c : pwd) {
        if (c >= 'A' && c <= 'Z') up = true;
        else if (c >= 'a' && c <= 'z') low = true;
        else if (c >= '0' && c <= '9') dig = true;
        else if (symbols.find(c) != std::string::npos) sym = true;
    }
    if (!up) { errorMsg = "Missing uppercase letter."; return false; }
    if (!low) { errorMsg = "Missing lowercase letter."; return false; }
    if (!dig) { errorMsg = "Missing digit."; return false; }
    if (!sym) { errorMsg = "Missing symbol (!@#$%^&*())."; return false; }
    return true;
}

bool verifyPassword(HANDLE hVault, const VaultHeader& header, const std::string& pwd, BYTE* outEncKey, BYTE* outAuthKey) {
    BYTE tempEnc[32];
    BYTE tempAuth[32];
    if (!deriveKey(pwd, header.salt, tempEnc, tempAuth)) {
        wipeSensitiveData(tempEnc, 32); wipeSensitiveData(tempAuth, 32); return false;
    }

    BCRYPT_ALG_HANDLE hAlg = NULL; 
    BCRYPT_KEY_HANDLE hKey = NULL;
    
    if ((LONG)BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0) != 0x00000000L) {
        wipeSensitiveData(tempEnc, 32); wipeSensitiveData(tempAuth, 32); return false;
    }
    (void)BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM, (ULONG)sizeof(L"ChainingModeGCM"), 0);
    (void)BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, (PUCHAR)tempEnc, (ULONG)32, 0);

    BYTE outTag[16] = {0};
    ULONG outBytes = 0;
    BYTE inBuf[32]; memcpy(inBuf, "SECUREVAULT2_PASSWORD_VERIFY_TAG", 32);
    BYTE outBuf[32];

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = (PUCHAR)header.pwdVerifyIV;
    authInfo.cbNonce = (ULONG)12;
    authInfo.pbTag = (PUCHAR)outTag;
    authInfo.cbTag = (ULONG)16;
    authInfo.pbAuthData = (PUCHAR)tempAuth;
    authInfo.cbAuthData = (ULONG)32;

    LONG status = (LONG)BCryptEncrypt(hKey, (PUCHAR)inBuf, (ULONG)32, &authInfo, NULL, 0, (PUCHAR)outBuf, (ULONG)32, &outBytes, 0);

    (void)BCryptDestroyKey(hKey);
    (void)BCryptCloseAlgorithmProvider(hAlg, 0);
    wipeSensitiveData(inBuf, 32);
    wipeSensitiveData(outBuf, 32);

    if (status == 0x00000000L && constTimeEqual(outTag, header.pwdVerifyTag, 16)) {
        memcpy(outEncKey, tempEnc, 32);
        memcpy(outAuthKey, tempAuth, 32);
        wipeSensitiveData(tempEnc, 32); wipeSensitiveData(tempAuth, 32);
        return true;
    } else {
        wipeSensitiveData(tempEnc, 32); wipeSensitiveData(tempAuth, 32);
        return false;
    }
}

// ==========================================
// GUI HELPERS
// ==========================================
void SetStatus(const char* msg) {
    strncpy_s(g_StatusText, msg, _TRUNCATE);
    InvalidateRect(g_hMainWnd, NULL, TRUE);
}

void CenterWindow(HWND hwnd, HWND hParent) {
    RECT rc, rcParent;
    GetWindowRect(hwnd, &rc);
    if (hParent) GetWindowRect(hParent, &rcParent);
    else {
        rcParent.left = 0; rcParent.top = 0;
        rcParent.right = GetSystemMetrics(SM_CXSCREEN);
        rcParent.bottom = GetSystemMetrics(SM_CYSCREEN);
    }
    int x = rcParent.left + (rcParent.right - rcParent.left - (rc.right - rc.left)) / 2;
    int y = rcParent.top + (rcParent.bottom - rcParent.top - (rc.bottom - rc.top)) / 2;
    SetWindowPos(hwnd, HWND_TOP, x, y, 0, 0, SWP_NOSIZE);
}

// ==========================================
// WINDOW PROCS
// ==========================================

// --- Progress Dialog ---
static int g_ProgressPct = 0;
LRESULT CALLBACK ProgressProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_APP + 1:
        g_ProgressPct = (int)wParam;
        InvalidateRect(hwnd, NULL, FALSE);
        return 0;
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);
        RECT rcClient; GetClientRect(hwnd, &rcClient);
        
        HBRUSH hBg = CreateSolidBrush(RGB(18, 18, 28));
        FillRect(hdc, &rcClient, hBg);
        DeleteObject(hBg);
        
        SetBkMode(hdc, TRANSPARENT);
        SetTextColor(hdc, RGB(255, 255, 255));
        SelectObject(hdc, g_hFontSub);
        
        RECT rText = {0, 20, 400, 40};
        DrawTextA(hdc, "Encrypting file...", -1, &rText, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        
        // Progress bar container 360x24
        RECT rBar = {20, 60, 380, 84};
        HBRUSH hBarBg = CreateSolidBrush(RGB(40, 40, 70));
        FillRect(hdc, &rBar, hBarBg);
        DeleteObject(hBarBg);
        
        // Fill
        int w = (360 * g_ProgressPct) / 100;
        RECT rFill = {20, 60, 20 + w, 84};
        HBRUSH hFill = CreateSolidBrush(RGB(0, 180, 220));
        FillRect(hdc, &rFill, hFill);
        DeleteObject(hFill);
        
        // Text percent
        char pctStr[16]; snprintf(pctStr, sizeof(pctStr), "%d%%", g_ProgressPct);
        SelectObject(hdc, g_hFontMono);
        DrawTextA(hdc, pctStr, -1, &rBar, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        
        // Border
        HPEN hPen = CreatePen(PS_SOLID, 1, RGB(40,40,70));
        HPEN hOld = (HPEN)SelectObject(hdc, hPen);
        SelectObject(hdc, GetStockObject(NULL_BRUSH));
        Rectangle(hdc, 0, 0, rcClient.right, rcClient.bottom);
        SelectObject(hdc, hOld);
        DeleteObject(hPen);
        
        EndPaint(hwnd, &ps);
        return 0;
    }
    }
    return DefWindowProc(hwnd, msg, wParam, lParam);
}

// --- Input Dialog ---
LRESULT CALLBACK InputBoxProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_INITDIALOG:
        CenterWindow(hwnd, GetParent(hwnd));
        return TRUE;
    case WM_COMMAND:
        if (LOWORD(wParam) == IDOK) {
            char buf[256] = {0};
            GetDlgItemTextA(hwnd, 101, buf, 256);
            g_InputBoxText = buf;
            EndDialog(hwnd, IDOK);
            return TRUE;
        } else if (LOWORD(wParam) == IDCANCEL) {
            EndDialog(hwnd, IDCANCEL);
            return TRUE;
        }
        break;
    }
    return FALSE;
}

// --- Result Box Dialog ---
LRESULT CALLBACK ResultBoxProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE: {
        HWND hEdit = CreateWindowExA(0, "EDIT", "", WS_CHILD | WS_VISIBLE | WS_BORDER | WS_VSCROLL | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL, 10, 10, 360, 220, hwnd, (HMENU)(UINT_PTR)1, g_hInst, NULL);
        SendMessageA(hEdit, WM_SETFONT, (WPARAM)g_hFontMono, FALSE);
        SendMessageA(hEdit, WM_SETTEXT, 0, (LPARAM)g_ListResultText.c_str());
        CreateWindowExA(0, "BUTTON", "Close", WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON, 140, 240, 100, 30, hwnd, (HMENU)(UINT_PTR)2, g_hInst, NULL);
        CenterWindow(hwnd, GetParent(hwnd));
        break;
    }
    case WM_COMMAND:
        if (LOWORD(wParam) == 2) DestroyWindow(hwnd);
        break;
    }
    return DefWindowProc(hwnd, msg, wParam, lParam);
}

// --- Virtual Keyboard Dialog ---
static int kR = 0, kC = 0;
static std::string kPwd = "";

LRESULT CALLBACK KeyboardProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    const char* kRows[6][10] = {
        {"A","B","C","D","E","F","G","H","I","J"},
        {"K","L","M","N","O","P","Q","R","S","T"},
        {"U","V","W","X","Y","Z","0","1","2","3"},
        {"4","5","6","7","8","9","!","@","#","$"},
        {"%","^","&","*","(",")","-","_","+","="},
        {"SPACE", "BACK", "DONE", "", "", "", "", "", "", ""}
    };
    int kCols[6] = {10, 10, 10, 10, 10, 3};

    switch (msg) {
    case WM_CREATE: {
        CREATESTRUCT* cs = (CREATESTRUCT*)lParam;
        SetWindowLongPtrA(hwnd, GWLP_USERDATA, (LONG_PTR)cs->lpCreateParams);
        kR = 0; kC = 0; kPwd = "";
        CenterWindow(hwnd, GetParent(hwnd));
        return 0;
    }
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);
        RECT rcClient; GetClientRect(hwnd, &rcClient);

        HBRUSH hBg = CreateSolidBrush(RGB(12, 12, 22));
        FillRect(hdc, &rcClient, hBg);
        DeleteObject(hBg);

        HPEN hBorder = CreatePen(PS_SOLID, 2, RGB(0, 180, 220));
        HPEN hOldPen = (HPEN)SelectObject(hdc, hBorder);
        HBRUSH hOldBrush = (HBRUSH)SelectObject(hdc, GetStockObject(NULL_BRUSH));
        Rectangle(hdc, 10, 10, rcClient.right - 10, rcClient.bottom - 10);
        SelectObject(hdc, hOldBrush);
        SelectObject(hdc, hOldPen);
        DeleteObject(hBorder);

        SetBkMode(hdc, TRANSPARENT);
        
        // Pass Area
        RECT rPass = {20, 20, rcClient.right - 20, 60};
        HBRUSH hPassBg = CreateSolidBrush(RGB(20, 20, 35));
        FillRect(hdc, &rPass, hPassBg);
        DeleteObject(hPassBg);

        SetTextColor(hdc, RGB(255, 255, 255));
        SelectObject(hdc, g_hFontMono);
        std::string disp = "Password: ";
        for (size_t i = 0; i < kPwd.length(); ++i) disp += "*";
        DrawTextA(hdc, disp.c_str(), -1, &rPass, DT_LEFT | DT_VCENTER | DT_SINGLELINE);

        // Grid
        int startY = 80;
        int cellW = 40, cellH = 36, gap = 3;
        for (int r = 0; r < 6; ++r) {
            int rowW = (r < 5) ? (10 * cellW + 9 * gap) : (3 * 120 + 2 * gap);
            int startX = (rcClient.right - rowW) / 2;
            
            for (int c = 0; c < kCols[r]; ++c) {
                int cx = startX + c * ((r < 5) ? (cellW + gap) : (120 + gap));
                int cw = (r < 5) ? cellW : 120;
                RECT rcCell = {cx, startY + r * (cellH + gap), cx + cw, startY + r * (cellH + gap) + cellH};
                
                bool isSel = (r == kR && c == kC);
                HBRUSH cBg = CreateSolidBrush(isSel ? RGB(0, 140, 180) : RGB(30, 30, 50));
                FillRect(hdc, &rcCell, cBg);
                DeleteObject(cBg);

                HPEN cPen = CreatePen(PS_SOLID, 1, isSel ? RGB(0, 220, 255) : RGB(50, 50, 80));
                hOldPen = (HPEN)SelectObject(hdc, cPen);
                hOldBrush = (HBRUSH)SelectObject(hdc, GetStockObject(NULL_BRUSH));
                Rectangle(hdc, rcCell.left, rcCell.top, rcCell.right, rcCell.bottom);
                SelectObject(hdc, hOldBrush);
                SelectObject(hdc, hOldPen);
                DeleteObject(cPen);

                SetTextColor(hdc, isSel ? RGB(255, 255, 255) : RGB(180, 220, 255));
                DrawTextA(hdc, kRows[r][c], -1, &rcCell, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
            }
        }
        EndPaint(hwnd, &ps);
        return 0;
    }
    case WM_KEYDOWN: {
        int vk = (int)wParam;
        if (vk == VK_UP) {
            kR = (kR > 0) ? kR - 1 : 5;
            if (kR == 5) kC = (kC / 4 < 3) ? kC / 4 : 2;
        } else if (vk == VK_DOWN) {
            kR = (kR < 5) ? kR + 1 : 0;
            if (kR == 5) kC = (kC / 4 < 3) ? kC / 4 : 2;
            else if (kR == 0) kC = kC * 4; // Map back
            if (kC >= kCols[kR]) kC = kCols[kR] - 1;
        } else if (vk == VK_LEFT) {
            kC = (kC > 0) ? kC - 1 : kCols[kR] - 1;
        } else if (vk == VK_RIGHT) {
            kC = (kC < kCols[kR] - 1) ? kC + 1 : 0;
        } else if (vk == VK_RETURN) {
            if (kR < 5) kPwd += kRows[kR][kC];
            else {
                if (kC == 0) kPwd += " ";
                else if (kC == 1) { if (!kPwd.empty()) kPwd.pop_back(); }
                else if (kC == 2) {
                    std::string* pOut = (std::string*)GetWindowLongPtrA(hwnd, GWLP_USERDATA);
                    if (pOut) *pOut = kPwd;
                    DestroyWindow(hwnd);
                    return 0;
                }
            }
        } else if (vk == VK_BACK) {
            if (!kPwd.empty()) kPwd.pop_back();
        } else if (vk == VK_ESCAPE) {
            std::string* pOut = (std::string*)GetWindowLongPtrA(hwnd, GWLP_USERDATA);
            if (pOut) *pOut = "";
            DestroyWindow(hwnd);
            return 0;
        }
        InvalidateRect(hwnd, NULL, FALSE);
        return 0;
    }
    }
    return DefWindowProc(hwnd, msg, wParam, lParam);
}

std::string getPasswordViaKeyboard(HWND hParent, const char* title) {
    std::string result = "";
    HWND hDlg = CreateWindowExA(WS_EX_DLGMODALFRAME, "SecureVault2_Kbd", title, WS_POPUP | WS_CAPTION | DS_MODALFRAME, 0, 0, 480, 340, hParent, NULL, g_hInst, &result);
    EnableWindow(hParent, FALSE);
    ShowWindow(hDlg, SW_SHOW);
    MSG msg;
    while (IsWindow(hDlg) && GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    EnableWindow(hParent, TRUE);
    SetForegroundWindow(hParent);
    return result;
}

// ==========================================
// GUI FLOW LOGIC
// ==========================================
bool guiAuthenticate(HWND hParent, HANDLE hVault, VaultHeader& header, BYTE* outEncKey, BYTE* outAuthKey) {
    if (header.failedAttempts >= 5) {
        uint64_t waitTime = (header.failedAttempts - 4ULL) * 30ULL;
        FILETIME ftNow; GetSystemTimeAsFileTime(&ftNow);
        ULARGE_INTEGER uli; uli.LowPart = ftNow.dwLowDateTime; uli.HighPart = ftNow.dwHighDateTime;
        uint64_t now = uli.QuadPart;
        uint64_t elapsedSec = (now - header.lastFailTime) / 10000000ULL;
        if (elapsedSec < waitTime) {
            uint64_t remaining = waitTime - elapsedSec;
            char msg[256];
            snprintf(msg, sizeof(msg), "Lockout active. Try again in %llu seconds.", (unsigned long long)remaining);
            MessageBoxA(hParent, msg, "Locked", MB_ICONWARNING);
            return false;
        }
    }

    std::string pwd = getPasswordViaKeyboard(hParent, "Enter Vault Password");
    if (pwd.empty()) return false;

    bool success = verifyPassword(hVault, header, pwd, outEncKey, outAuthKey);
    wipeSensitiveData(pwd.data(), pwd.length());

    if (!success) {
        header.failedAttempts++;
        FILETIME ftNow; GetSystemTimeAsFileTime(&ftNow);
        ULARGE_INTEGER uli; uli.LowPart = ftNow.dwLowDateTime; uli.HighPart = ftNow.dwHighDateTime;
        header.lastFailTime = uli.QuadPart;
        computeHeaderHMAC(header, header.headerHMAC);
        LARGE_INTEGER liPos; liPos.QuadPart = 0; SetFilePointerEx(hVault, liPos, NULL, FILE_BEGIN);
        DWORD bw; WriteFile(hVault, &header, sizeof(header), &bw, NULL);
        MessageBoxA(hParent, "Wrong password — vault locked", "Error", MB_ICONERROR);
        return false;
    } else {
        if (header.failedAttempts > 0) {
            header.failedAttempts = 0;
            header.lastFailTime = 0;
            computeHeaderHMAC(header, header.headerHMAC);
            LARGE_INTEGER liPos; liPos.QuadPart = 0; SetFilePointerEx(hVault, liPos, NULL, FILE_BEGIN);
            DWORD bw; WriteFile(hVault, &header, sizeof(header), &bw, NULL);
        }
        return true;
    }
}

void CreateVaultFlow() {
    SetForegroundWindow(g_hMainWnd);
    char szFile[MAX_PATH]; ZeroMemory(szFile, sizeof(szFile)); 
    OPENFILENAMEA ofn; ZeroMemory(&ofn, sizeof(ofn)); 
    ofn.lStructSize = sizeof(ofn); ofn.hwndOwner = g_hMainWnd; ofn.lpstrFile = szFile; 
    ofn.nMaxFile = sizeof(szFile); ofn.lpstrFilter = "Vault Files\0*.vault\0All Files\0*.*\0"; 
    ofn.nFilterIndex = 1; ofn.lpstrDefExt = "vault"; 
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_OVERWRITEPROMPT | OFN_NOCHANGEDIR | OFN_EXPLORER; 
    if (!GetSaveFileNameA(&ofn)) { 
        DWORD err = CommDlgExtendedError(); 
        if (err != 0) { char msg[64]; snprintf(msg, sizeof(msg), "Dialog error: %lu", err); MessageBoxA(g_hMainWnd, msg, "Error", MB_OK | MB_ICONERROR); } 
        return; 
    } 
    if (szFile[0] == '\0') return;

    std::string vaultPath = szFile;
    if (vaultPath.size() < 6 || vaultPath.substr(vaultPath.size() - 6) != ".vault") {
        vaultPath += ".vault";
    }

    std::string pwd, err;
    while (true) {
        pwd = getPasswordViaKeyboard(g_hMainWnd, "Set Password");
        if (pwd.empty()) return;
        if (validatePassword(pwd, err)) break;
        MessageBoxA(g_hMainWnd, err.c_str(), "Invalid Password", MB_ICONERROR);
    }

    VaultHeader header = {0};
    memcpy(header.magic, "SVL2", 4);
    header.version = 1;
    header.iterations = 500000;
    (void)BCryptGenRandom(NULL, (PUCHAR)header.salt, (ULONG)32, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    (void)BCryptGenRandom(NULL, (PUCHAR)header.pwdVerifyIV, (ULONG)12, BCRYPT_USE_SYSTEM_PREFERRED_RNG);

    header.fileCount = 0;
    header.failedAttempts = 0;
    header.lastFailTime = 0;
    header.dataOffset = sizeof(VaultHeader);
    header.entriesOffset = sizeof(VaultHeader);

    BYTE encKey[32], authKey[32];
    deriveKey(pwd, header.salt, encKey, authKey);
    wipeSensitiveData(pwd.data(), pwd.length());

    {
        BCRYPT_ALG_HANDLE hAlg = NULL; 
        BCRYPT_KEY_HANDLE hKey = NULL;
        (void)BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
        (void)BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM, (ULONG)sizeof(L"ChainingModeGCM"), 0);
        (void)BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, (PUCHAR)encKey, (ULONG)32, 0);

        BYTE outTag[16] = {0};
        ULONG outBytes = 0;
        BYTE inBuf[32]; memcpy(inBuf, "SECUREVAULT2_PASSWORD_VERIFY_TAG", 32);
        BYTE outBuf[32];

        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
        BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
        authInfo.pbNonce = (PUCHAR)header.pwdVerifyIV;
        authInfo.cbNonce = (ULONG)12;
        authInfo.pbTag = (PUCHAR)outTag;
        authInfo.cbTag = (ULONG)16;
        authInfo.pbAuthData = (PUCHAR)authKey;
        authInfo.cbAuthData = (ULONG)32;

        (void)BCryptEncrypt(hKey, (PUCHAR)inBuf, (ULONG)32, &authInfo, NULL, 0, (PUCHAR)outBuf, (ULONG)32, &outBytes, 0);

        memcpy(header.pwdVerifyTag, outTag, 16);

        (void)BCryptDestroyKey(hKey);
        (void)BCryptCloseAlgorithmProvider(hAlg, 0);
        wipeSensitiveData(inBuf, 32); wipeSensitiveData(outBuf, 32);
    }

    HANDLE hVault = CreateFileA(vaultPath.c_str(), GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hVault == INVALID_HANDLE_VALUE) {
        wipeSensitiveData(encKey, 32); wipeSensitiveData(authKey, 32);
        MessageBoxA(g_hMainWnd, "Out of disk space or write error", "Error", MB_ICONERROR);
        return;
    }
    
    DWORD bw;
    WriteFile(hVault, &header, sizeof(header), &bw, NULL);
    computeVaultHMAC(hVault, header.entriesOffset, authKey, header.vaultAuthTag);
    computeHeaderHMAC(header, header.headerHMAC);
    
    LARGE_INTEGER liPos; liPos.QuadPart = 0; SetFilePointerEx(hVault, liPos, NULL, FILE_BEGIN);
    if (!WriteFile(hVault, &header, sizeof(header), &bw, NULL)) {
        MessageBoxA(g_hMainWnd, "Out of disk space or write error", "Error", MB_ICONERROR);
    }

    CloseHandle(hVault);
    wipeSensitiveData(encKey, 32); wipeSensitiveData(authKey, 32);
    std::string st = "Vault created: " + vaultPath;
    SetStatus(st.c_str());
}

void LockFileFlow() {
    SetForegroundWindow(g_hMainWnd);
    
    char szSrcFile[MAX_PATH]; ZeroMemory(szSrcFile, sizeof(szSrcFile)); 
    OPENFILENAMEA ofn1; ZeroMemory(&ofn1, sizeof(ofn1)); 
    ofn1.lStructSize = sizeof(ofn1); ofn1.hwndOwner = g_hMainWnd; ofn1.lpstrFile = szSrcFile; 
    ofn1.nMaxFile = sizeof(szSrcFile); ofn1.lpstrTitle = "Select File to Lock";
    ofn1.lpstrFilter = "All Files\0*.*\0"; ofn1.nFilterIndex = 1; 
    ofn1.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_NOCHANGEDIR | OFN_EXPLORER; 
    if (!GetOpenFileNameA(&ofn1)) { 
        DWORD err = CommDlgExtendedError(); 
        if (err != 0) { char msg[64]; snprintf(msg, sizeof(msg), "Dialog error: %lu", err); MessageBoxA(g_hMainWnd, msg, "Error", MB_OK | MB_ICONERROR); } 
        return; 
    } 
    if (szSrcFile[0] == '\0') return;

    char szVaultFile[MAX_PATH]; ZeroMemory(szVaultFile, sizeof(szVaultFile)); 
    OPENFILENAMEA ofn2; ZeroMemory(&ofn2, sizeof(ofn2)); 
    ofn2.lStructSize = sizeof(ofn2); ofn2.hwndOwner = g_hMainWnd; ofn2.lpstrFile = szVaultFile; 
    ofn2.nMaxFile = sizeof(szVaultFile); ofn2.lpstrTitle = "Select Vault";
    ofn2.lpstrFilter = "Vault Files\0*.vault\0All Files\0*.*\0"; ofn2.nFilterIndex = 1; 
    ofn2.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_NOCHANGEDIR | OFN_EXPLORER; 
    if (!GetOpenFileNameA(&ofn2)) { 
        DWORD err = CommDlgExtendedError(); 
        if (err != 0) { char msg[64]; snprintf(msg, sizeof(msg), "Dialog error: %lu", err); MessageBoxA(g_hMainWnd, msg, "Error", MB_OK | MB_ICONERROR); } 
        return; 
    } 
    if (szVaultFile[0] == '\0') return;

    std::string backupPath = std::string(szVaultFile) + ".bak";
    CopyFileA(szVaultFile, backupPath.c_str(), FALSE);

    HANDLE hIn = INVALID_HANDLE_VALUE;
    HANDLE hVault = INVALID_HANDLE_VALUE;
    HANDLE hTemp = INVALID_HANDLE_VALUE;
    char tempPath[MAX_PATH] = {0};
    BYTE encKey[32] = {0};
    BYTE authKey[32] = {0};
    bool isSuccess = false;

    VaultHeader header;
    uint64_t vSize = 0;
    FileEntry newEntry = {0};
    std::string baseName;
    DWORD bw;

    hIn = CreateFileA(szSrcFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (hIn == INVALID_HANDLE_VALUE) { MessageBoxA(g_hMainWnd, "File missing or cannot be opened", "Error", MB_ICONERROR); goto cleanup; }
    
    LARGE_INTEGER sz; GetFileSizeEx(hIn, &sz);
    if (sz.QuadPart == 0) { MessageBoxA(g_hMainWnd, "Cannot lock empty files.", "Error", MB_ICONERROR); goto cleanup; }

    hVault = CreateFileA(szVaultFile, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hVault == INVALID_HANDLE_VALUE) { MessageBoxA(g_hMainWnd, "Vault file missing or cannot be opened", "Error", MB_ICONERROR); goto cleanup; }

    if (!validateVault(hVault, header, vSize)) {
        MessageBoxA(g_hMainWnd, "Invalid or corrupted vault file", "Error", MB_ICONERROR); goto cleanup;
    }

    if (!guiAuthenticate(g_hMainWnd, hVault, header, encKey, authKey)) goto cleanup;

    char tempDir[MAX_PATH];
    GetTempPathA(MAX_PATH, tempDir);
    GetTempFileNameA(tempDir, "SVL", 0, tempPath);
    
    hTemp = CreateFileA(tempPath, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hTemp == INVALID_HANDLE_VALUE) {
        MessageBoxA(g_hMainWnd, "Out of disk space or write error", "Error", MB_ICONERROR); goto cleanup;
    }

    {
        LARGE_INTEGER liPos1; liPos1.QuadPart = 0; SetFilePointerEx(hVault, liPos1, NULL, FILE_BEGIN);
        uint64_t toCopy = header.entriesOffset;
        uint64_t copied = 0;
        static BYTE copyBuf[CHUNK_SIZE];
        
        while (copied < toCopy) {
            DWORD chunk = (DWORD)( ((toCopy - copied) > (uint64_t)CHUNK_SIZE) ? (uint64_t)CHUNK_SIZE : (toCopy - copied) );
            DWORD br, bwC;
            if (!ReadFile(hVault, copyBuf, chunk, &br, NULL) || br == 0) goto cleanup;
            if (!WriteFile(hTemp, copyBuf, br, &bwC, NULL) || bwC != br) goto cleanup;
            copied += (uint64_t)br;
        }
    }

    baseName = szSrcFile;
    {
        size_t lastSlash = baseName.find_last_of("/\\");
        if (lastSlash != std::string::npos) baseName = baseName.substr(lastSlash + 1);
    }
    
    encryptName(baseName, encKey, authKey, newEntry.encryptedName, newEntry.nameLen, newEntry.fileIV, newEntry.nameAuthTag);
    newEntry.dataOffset = header.entriesOffset;
    newEntry.originalSize = (uint64_t)sz.QuadPart;
    newEntry.storedSize = 0;

    g_hProgressWnd = CreateWindowExA(0, "SecureVault2_Progress", "", WS_POPUP | WS_BORDER, 0, 0, 400, 120, g_hMainWnd, NULL, g_hInst, NULL);
    CenterWindow(g_hProgressWnd, g_hMainWnd);
    ShowWindow(g_hProgressWnd, SW_SHOW);
    g_ProgressPct = 0;

    if (!encryptFile(hIn, hTemp, encKey, authKey, newEntry)) {
        DestroyWindow(g_hProgressWnd); g_hProgressWnd = NULL;
        goto cleanup;
    }
    DestroyWindow(g_hProgressWnd); g_hProgressWnd = NULL;

    if (!verifyEntry(hTemp, newEntry, encKey, authKey)) {
        MessageBoxA(g_hMainWnd, "Encryption failed — vault unchanged", "Error", MB_ICONERROR);
        goto cleanup;
    }

    {
        LARGE_INTEGER pos;
        LARGE_INTEGER liPos2; liPos2.QuadPart = 0; SetFilePointerEx(hTemp, liPos2, &pos, FILE_CURRENT);

        LARGE_INTEGER liPos3; liPos3.QuadPart = (LONGLONG)header.entriesOffset; SetFilePointerEx(hVault, liPos3, NULL, FILE_BEGIN);
        for (uint32_t i = 0; i < header.fileCount; ++i) {
            FileEntry e; DWORD br;
            if (ReadFile(hVault, &e, sizeof(e), &br, NULL) && br == sizeof(e)) {
                if (!WriteFile(hTemp, &e, sizeof(e), &bw, NULL)) goto cleanup;
            }
        }

        header.entriesOffset = (uint64_t)pos.QuadPart;
        header.fileCount++;
        if (!WriteFile(hTemp, &newEntry, sizeof(newEntry), &bw, NULL)) goto cleanup;

        computeVaultHMAC(hTemp, header.entriesOffset, authKey, header.vaultAuthTag);
        computeHeaderHMAC(header, header.headerHMAC);

        LARGE_INTEGER liPos4; liPos4.QuadPart = 0; SetFilePointerEx(hTemp, liPos4, NULL, FILE_BEGIN);
        if (!WriteFile(hTemp, &header, sizeof(header), &bw, NULL)) goto cleanup;
    }

    isSuccess = true;

cleanup:
    if (hIn != INVALID_HANDLE_VALUE) CloseHandle(hIn);
    if (hVault != INVALID_HANDLE_VALUE) CloseHandle(hVault);
    if (hTemp != INVALID_HANDLE_VALUE) CloseHandle(hTemp);

    if (isSuccess && tempPath[0] != '\0') {
        if (!MoveFileExA(tempPath, szVaultFile, MOVEFILE_REPLACE_EXISTING)) {
            isSuccess = false;
        } else {
            tempPath[0] = '\0';
        }
    }

    if (tempPath[0] != '\0' && !isSuccess) {
        (void)DeleteFileA(tempPath);
    }
    wipeSensitiveData(encKey, 32); wipeSensitiveData(authKey, 32);

    if (!isSuccess) {
        CopyFileA(backupPath.c_str(), szVaultFile, FALSE);
        DeleteFileA(backupPath.c_str());
        MessageBoxA(g_hMainWnd, "Operation failed. Vault restored from backup.", "Error", MB_ICONERROR);
    } else {
        DeleteFileA(backupPath.c_str());
        if (MessageBoxA(g_hMainWnd, "Delete original file? This cannot be undone.", "Delete Original", MB_YESNO | MB_ICONQUESTION) == IDYES) {
            SHFILEOPSTRUCTA fileOp = {0};
            fileOp.wFunc = FO_DELETE;
            char szPath[MAX_PATH + 2] = {0};
            strcpy_s(szPath, szSrcFile);
            fileOp.pFrom = szPath;
            fileOp.fFlags = FOF_ALLOWUNDO | FOF_NOCONFIRMATION | FOF_NOERRORUI | FOF_SILENT;
            SHFileOperationA(&fileOp);
        }
        std::string st = "Locked: " + baseName;
        SetStatus(st.c_str());
    }
}

void UnlockFileFlow() {
    SetForegroundWindow(g_hMainWnd);
    char szVaultFile[MAX_PATH]; ZeroMemory(szVaultFile, sizeof(szVaultFile)); 
    OPENFILENAMEA ofn; ZeroMemory(&ofn, sizeof(ofn)); 
    ofn.lStructSize = sizeof(ofn); ofn.hwndOwner = g_hMainWnd; ofn.lpstrFile = szVaultFile; 
    ofn.nMaxFile = sizeof(szVaultFile); ofn.lpstrTitle = "Select Vault";
    ofn.lpstrFilter = "Vault Files\0*.vault\0All Files\0*.*\0"; ofn.nFilterIndex = 1; 
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_NOCHANGEDIR | OFN_EXPLORER; 
    if (!GetOpenFileNameA(&ofn)) { 
        DWORD err = CommDlgExtendedError(); 
        if (err != 0) { char msg[64]; snprintf(msg, sizeof(msg), "Dialog error: %lu", err); MessageBoxA(g_hMainWnd, msg, "Error", MB_OK | MB_ICONERROR); } 
        return; 
    } 
    if (szVaultFile[0] == '\0') return;

    g_InputBoxText = "";
    
    HGLOBAL hGlobal = GlobalAlloc(GMEM_ZEROINIT, 1024);
    if (hGlobal) {
        LPWORD p = (LPWORD)GlobalLock(hGlobal);
        
        LPDLGTEMPLATE lpdit = (LPDLGTEMPLATE)p;
        lpdit->style = DS_MODALFRAME | WS_POPUP | WS_CAPTION | WS_SYSMENU | DS_CENTER;
        lpdit->cdit = 3;
        lpdit->x = 0; lpdit->y = 0; lpdit->cx = 200; lpdit->cy = 70;
        
        p = (LPWORD)(lpdit + 1);
        *p++ = 0; // menu
        *p++ = 0; // class
        
        LPCWSTR title = L"Enter filename to extract";
        int n = lstrlenW(title);
        CopyMemory(p, title, n * sizeof(WCHAR));
        p += n; *p++ = 0;
        
        #define ALIGN_DWORD(ptr) (((ULONG_PTR)(ptr) + 3) & ~3)
        p = (LPWORD)ALIGN_DWORD(p);
        
        // Edit
        LPDITEMTEMPLATE lpditi = (LPDITEMTEMPLATE)p;
        lpditi->style = WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL;
        lpditi->x = 10; lpditi->y = 15; lpditi->cx = 180; lpditi->cy = 14;
        lpditi->id = 101;
        p = (LPWORD)(lpditi + 1);
        *p++ = 0xFFFF; *p++ = 0x0081; 
        *p++ = 0; 
        *p++ = 0; 
        p = (LPWORD)ALIGN_DWORD(p);
        
        // OK
        lpditi = (LPDITEMTEMPLATE)p;
        lpditi->style = WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON;
        lpditi->x = 40; lpditi->y = 40; lpditi->cx = 50; lpditi->cy = 14;
        lpditi->id = IDOK;
        p = (LPWORD)(lpditi + 1);
        *p++ = 0xFFFF; *p++ = 0x0080; 
        LPCWSTR btnOK = L"OK";
        n = lstrlenW(btnOK);
        CopyMemory(p, btnOK, n * sizeof(WCHAR));
        p += n; *p++ = 0;
        *p++ = 0;
        p = (LPWORD)ALIGN_DWORD(p);
        
        // Cancel
        lpditi = (LPDITEMTEMPLATE)p;
        lpditi->style = WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON;
        lpditi->x = 110; lpditi->y = 40; lpditi->cx = 50; lpditi->cy = 14;
        lpditi->id = IDCANCEL;
        p = (LPWORD)(lpditi + 1);
        *p++ = 0xFFFF; *p++ = 0x0080;
        LPCWSTR btnCancel = L"Cancel";
        n = lstrlenW(btnCancel);
        CopyMemory(p, btnCancel, n * sizeof(WCHAR));
        p += n; *p++ = 0;
        *p++ = 0;
        
        GlobalUnlock(hGlobal);
        DialogBoxIndirectParamA(g_hInst, (LPDLGTEMPLATE)hGlobal, g_hMainWnd, (DLGPROC)InputBoxProc, 0);
        GlobalFree(hGlobal);
    }
    
    if (g_InputBoxText.empty()) return;
    std::string targetFile = g_InputBoxText;

    HANDLE hVault = CreateFileA(szVaultFile, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hVault == INVALID_HANDLE_VALUE) { MessageBoxA(g_hMainWnd, "Vault file missing or cannot be opened", "Error", MB_ICONERROR); return; }

    uint64_t vSize = 0;
    VaultHeader header;
    if (!validateVault(hVault, header, vSize)) {
        MessageBoxA(g_hMainWnd, "Invalid or corrupted vault file", "Error", MB_ICONERROR); CloseHandle(hVault); return;
    }

    BYTE encKey[32], authKey[32];
    if (!guiAuthenticate(g_hMainWnd, hVault, header, encKey, authKey)) { CloseHandle(hVault); return; }

    if (!verifyVaultHMAC(hVault, header, authKey)) {
        MessageBoxA(g_hMainWnd, "Vault has been tampered with or corrupted", "Error", MB_ICONERROR);
        wipeSensitiveData(encKey, 32); wipeSensitiveData(authKey, 32); CloseHandle(hVault); return;
    }

    bool found = false;
    LARGE_INTEGER liPos; liPos.QuadPart = (LONGLONG)header.entriesOffset; SetFilePointerEx(hVault, liPos, NULL, FILE_BEGIN);
    for (uint32_t i = 0; i < header.fileCount; ++i) {
        FileEntry e; DWORD br;
        if (!ReadFile(hVault, &e, sizeof(e), &br, NULL) || br != sizeof(e)) break;
        if (!isValidEntry(e, vSize)) continue;

        std::string name;
        if (decryptName(e.encryptedName, e.nameLen, encKey, authKey, e.fileIV, e.nameAuthTag, name)) {
            if (name == targetFile) {
                found = true;
                if (decryptFile(e, hVault, name, encKey, authKey)) {
                    std::string st = "Unlocked: " + name;
                    SetStatus(st.c_str());
                } else {
                    MessageBoxA(g_hMainWnd, "Out of disk space or write error", "Error", MB_ICONERROR);
                }
                break;
            }
        }
    }
    
    if (!found) MessageBoxA(g_hMainWnd, "File not found in vault", "Error", MB_ICONERROR);
    wipeSensitiveData(encKey, 32); wipeSensitiveData(authKey, 32); CloseHandle(hVault);
}

void ListVerifyFlow() {
    SetForegroundWindow(g_hMainWnd);
    char szVaultFile[MAX_PATH]; ZeroMemory(szVaultFile, sizeof(szVaultFile)); 
    OPENFILENAMEA ofn; ZeroMemory(&ofn, sizeof(ofn)); 
    ofn.lStructSize = sizeof(ofn); ofn.hwndOwner = g_hMainWnd; ofn.lpstrFile = szVaultFile; 
    ofn.nMaxFile = sizeof(szVaultFile); ofn.lpstrTitle = "Select Vault";
    ofn.lpstrFilter = "Vault Files\0*.vault\0All Files\0*.*\0"; ofn.nFilterIndex = 1; 
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_NOCHANGEDIR | OFN_EXPLORER; 
    if (!GetOpenFileNameA(&ofn)) { 
        DWORD err = CommDlgExtendedError(); 
        if (err != 0) { char msg[64]; snprintf(msg, sizeof(msg), "Dialog error: %lu", err); MessageBoxA(g_hMainWnd, msg, "Error", MB_OK | MB_ICONERROR); } 
        return; 
    } 
    if (szVaultFile[0] == '\0') return;

    HANDLE hVault = CreateFileA(szVaultFile, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hVault == INVALID_HANDLE_VALUE) { MessageBoxA(g_hMainWnd, "Vault file missing or cannot be opened", "Error", MB_ICONERROR); return; }

    uint64_t vSize = 0;
    VaultHeader header;
    if (!validateVault(hVault, header, vSize)) {
        MessageBoxA(g_hMainWnd, "Invalid or corrupted vault file", "Error", MB_ICONERROR); CloseHandle(hVault); return;
    }

    BYTE encKey[32], authKey[32];
    if (!guiAuthenticate(g_hMainWnd, hVault, header, encKey, authKey)) { CloseHandle(hVault); return; }

    if (!verifyVaultHMAC(hVault, header, authKey)) {
        MessageBoxA(g_hMainWnd, "Vault has been tampered with or corrupted", "Error", MB_ICONERROR);
        wipeSensitiveData(encKey, 32); wipeSensitiveData(authKey, 32); CloseHandle(hVault); return;
    }

    std::string res = "Files in vault:\r\n-----------------------\r\n";
    uint32_t okCount = 0, corruptCount = 0;

    for (uint32_t i = 0; i < header.fileCount; ++i) {
        LARGE_INTEGER liPos; liPos.QuadPart = (LONGLONG)header.entriesOffset + (LONGLONG)i * (LONGLONG)sizeof(FileEntry); SetFilePointerEx(hVault, liPos, NULL, FILE_BEGIN);
        FileEntry e; DWORD br;
        if (ReadFile(hVault, &e, sizeof(e), &br, NULL) && br == sizeof(e)) {
            if (!isValidEntry(e, vSize)) { res += "Corrupted entry skipped\r\n"; corruptCount++; continue; }

            std::string name;
            if (!decryptName(e.encryptedName, e.nameLen, encKey, authKey, e.fileIV, e.nameAuthTag, name)) {
                res += "[Name Decrypt Failed] : FAIL\r\n"; corruptCount++; continue;
            }

            if (verifyEntry(hVault, e, encKey, authKey)) {
                res += name + "[" + formatSize(e.originalSize) + "] : PASS\r\n"; okCount++;
            } else {
                res += name + "[" + formatSize(e.originalSize) + "] : FAIL\r\n"; corruptCount++;
            }
        }
    }
    wipeSensitiveData(encKey, 32); wipeSensitiveData(authKey, 32); CloseHandle(hVault);

    char summary[128]; snprintf(summary, sizeof(summary), "\r\nTotal: %u OK, %u Corrupted", okCount, corruptCount);
    res += summary;

    g_ListResultText = res;
    HWND hRes = CreateWindowExA(WS_EX_DLGMODALFRAME, "SecureVault2_Result", "List & Verify", WS_POPUP | WS_CAPTION | DS_MODALFRAME, 0, 0, 400, 320, g_hMainWnd, NULL, g_hInst, NULL);
    EnableWindow(g_hMainWnd, FALSE);
    ShowWindow(hRes, SW_SHOW);
    MSG msg;
    while (IsWindow(hRes) && GetMessage(&msg, NULL, 0, 0)) { TranslateMessage(&msg); DispatchMessage(&msg); }
    EnableWindow(g_hMainWnd, TRUE);
    SetForegroundWindow(g_hMainWnd);
    SetStatus("Verification complete");
}

// --- Main Window Proc ---
LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE: {
        HMENU hSysMenu = GetSystemMenu(hwnd, FALSE);
        AppendMenuA(hSysMenu, MF_SEPARATOR, 0, NULL);
        AppendMenuA(hSysMenu, MF_STRING, 1000, "About SecureVault2...");

        CreateWindowExA(0, "BUTTON", "Create Vault", WS_CHILD|WS_VISIBLE|BS_OWNERDRAW, 160, 80, 200, 44, hwnd, (HMENU)(UINT_PTR)101, g_hInst, NULL);
        CreateWindowExA(0, "BUTTON", "Lock File", WS_CHILD|WS_VISIBLE|BS_OWNERDRAW, 160, 140, 200, 44, hwnd, (HMENU)(UINT_PTR)102, g_hInst, NULL);
        CreateWindowExA(0, "BUTTON", "Unlock File", WS_CHILD|WS_VISIBLE|BS_OWNERDRAW, 160, 200, 200, 44, hwnd, (HMENU)(UINT_PTR)103, g_hInst, NULL);
        CreateWindowExA(0, "BUTTON", "List & Verify", WS_CHILD|WS_VISIBLE|BS_OWNERDRAW, 160, 260, 200, 44, hwnd, (HMENU)(UINT_PTR)104, g_hInst, NULL);
        CenterWindow(hwnd, NULL);
        break;
    }
    case WM_SYSCOMMAND:
        if ((wParam & 0xFFF0) == 1000) {
            MessageBoxA(hwnd, "SecureVault2 " VAULT_VERSION "\nWin32 GUI Version", "About", MB_OK);
            return 0;
        }
        break;
    case WM_COMMAND: {
        int wmId = LOWORD(wParam);
        if (wmId == 101) CreateVaultFlow();
        else if (wmId == 102) LockFileFlow();
        else if (wmId == 103) UnlockFileFlow();
        else if (wmId == 104) ListVerifyFlow();
        break;
    }
    case WM_DRAWITEM: {
        DRAWITEMSTRUCT* dis = (DRAWITEMSTRUCT*)lParam;
        if (dis->CtlType == ODT_BUTTON) {
            bool isPressed = (dis->itemState & ODS_SELECTED);
            HBRUSH hBg = CreateSolidBrush(isPressed ? RGB(0, 100, 140) : RGB(0, 140, 180));
            HPEN hPen = CreatePen(PS_SOLID, 1, RGB(0, 180, 220));
            HGDIOBJ oldBrush = SelectObject(dis->hDC, hBg);
            HGDIOBJ oldPen = SelectObject(dis->hDC, hPen);
            
            Rectangle(dis->hDC, dis->rcItem.left, dis->rcItem.top, dis->rcItem.right, dis->rcItem.bottom);
            RoundRect(dis->hDC, dis->rcItem.left, dis->rcItem.top, dis->rcItem.right, dis->rcItem.bottom, 8, 8);
            
            SelectObject(dis->hDC, oldBrush); SelectObject(dis->hDC, oldPen);
            DeleteObject(hBg); DeleteObject(hPen);
            
            char text[64]; GetWindowTextA(dis->hwndItem, text, sizeof(text));
            SetBkMode(dis->hDC, TRANSPARENT);
            SetTextColor(dis->hDC, RGB(255, 255, 255));
            SelectObject(dis->hDC, g_hFontBtn);
            DrawTextA(dis->hDC, text, -1, &dis->rcItem, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        }
        return TRUE;
    }
    case WM_PAINT: {
        PAINTSTRUCT ps; HDC hdc = BeginPaint(hwnd, &ps);
        RECT rc; GetClientRect(hwnd, &rc);
        
        HBRUSH hBg = CreateSolidBrush(RGB(18, 18, 28));
        FillRect(hdc, &rc, hBg); DeleteObject(hBg);
        
        RECT rHead = {0, 0, 520, 60};
        HBRUSH hHeadBg = CreateSolidBrush(RGB(0, 180, 220));
        FillRect(hdc, &rHead, hHeadBg); DeleteObject(hHeadBg);
        
        SetBkMode(hdc, TRANSPARENT);
        SetTextColor(hdc, RGB(255, 255, 255));
        SelectObject(hdc, g_hFontTitle);
        RECT rTitle = {20, 10, 500, 35};
        DrawTextA(hdc, "SecureVault2", -1, &rTitle, DT_LEFT | DT_SINGLELINE);
        
        SetTextColor(hdc, RGB(200, 240, 255));
        SelectObject(hdc, g_hFontSub);
        RECT rSub = {20, 35, 500, 55};
        DrawTextA(hdc, VAULT_VERSION, -1, &rSub, DT_LEFT | DT_SINGLELINE);

        RECT rStatus = {0, rc.bottom - 30, 520, rc.bottom};
        HBRUSH hStatBg = CreateSolidBrush(RGB(10, 10, 20));
        FillRect(hdc, &rStatus, hStatBg); DeleteObject(hStatBg);
        
        SetTextColor(hdc, RGB(255, 255, 255));
        SelectObject(hdc, g_hFontStatus);
        rStatus.left += 10;
        DrawTextA(hdc, g_StatusText, -1, &rStatus, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
        
        EndPaint(hwnd, &ps);
        return 0;
    }
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProc(hwnd, msg, wParam, lParam);
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    g_hInst = hInstance;
    cleanupTempFiles();

    g_hFontTitle = CreateFontA(22, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, ANSI_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH, "Arial");
    g_hFontSub = CreateFontA(14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, ANSI_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH, "Arial");
    g_hFontBtn = CreateFontA(16, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, ANSI_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH, "Arial");
    g_hFontMono = CreateFontA(18, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, ANSI_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, FIXED_PITCH, "Consolas");
    g_hFontStatus = CreateFontA(14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, ANSI_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH, "Arial");

    WNDCLASSA wc = {0};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = NULL;
    wc.lpszClassName = "SecureVault2_Main";
    if (!RegisterClassA(&wc)) {
        MessageBoxA(NULL, "Failed to register SecureVault2_Main window class", "Error", MB_ICONERROR);
        return -1;
    }

    wc.lpfnWndProc = KeyboardProc;
    wc.lpszClassName = "SecureVault2_Kbd";
    if (!RegisterClassA(&wc)) {
        MessageBoxA(NULL, "Failed to register SecureVault2_Kbd window class", "Error", MB_ICONERROR);
        return -1;
    }

    wc.lpfnWndProc = ProgressProc;
    wc.lpszClassName = "SecureVault2_Progress";
    if (!RegisterClassA(&wc)) {
        MessageBoxA(NULL, "Failed to register SecureVault2_Progress window class", "Error", MB_ICONERROR);
        return -1;
    }

    wc.lpfnWndProc = ResultBoxProc;
    wc.lpszClassName = "SecureVault2_Result";
    if (!RegisterClassA(&wc)) {
        MessageBoxA(NULL, "Failed to register SecureVault2_Result window class", "Error", MB_ICONERROR);
        return -1;
    }

    RECT wr = {0, 0, 520, 420};
    AdjustWindowRectEx(&wr, WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX, FALSE, 0);

    g_hMainWnd = CreateWindowExA(0, "SecureVault2_Main", "SecureVault2 " VAULT_VERSION, 
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX | WS_VISIBLE, 
        CW_USEDEFAULT, CW_USEDEFAULT, wr.right - wr.left, wr.bottom - wr.top, 
        NULL, NULL, hInstance, NULL);

    if (!g_hMainWnd) {
        MessageBoxA(NULL, "Failed to create main window", "Error", MB_ICONERROR);
        return -1;
    }

    ShowWindow(g_hMainWnd, SW_SHOWNORMAL);
    UpdateWindow(g_hMainWnd);

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    DeleteObject(g_hFontTitle); DeleteObject(g_hFontSub); DeleteObject(g_hFontBtn);
    DeleteObject(g_hFontMono); DeleteObject(g_hFontStatus);
    return (int)msg.wParam;
}