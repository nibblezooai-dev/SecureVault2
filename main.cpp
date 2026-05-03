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
    BYTE reserved[186];
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

void wipeSensitiveData(const void* ptr, size_t size);
void SetStatus(const char* msg);
void CenterWindow(HWND hwnd, HWND hParent);
std::string getPasswordViaKeyboard(HWND hParent, const char* title);
LRESULT CALLBACK KeyboardProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
LRESULT CALLBACK ProgressProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
LRESULT CALLBACK InputBoxProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
LRESULT CALLBACK ResultBoxProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);

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
// UTILITY FUNCTIONS (UNCHANGED SECURITY)
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
    BCryptGenRandom(NULL, (PUCHAR)(void*)ptr, (ULONG)size, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
}

std::string formatSize(uint64_t bytes) {
    char buf[64];
    if (bytes >= 1024ULL * 1024 * 1024) snprintf(buf, sizeof(buf), "%.2f GB", bytes / (1024.0 * 1024 * 1024));
    else if (bytes >= 1024ULL * 1024) snprintf(buf, sizeof(buf), "%.2f MB", bytes / (1024.0 * 1024));
    else snprintf(buf, sizeof(buf), "%.2f KB", bytes / 1024.0);
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
                DeleteFileA(fullPath.c_str());
            }
        } while (FindNextFileA(hFind, &fd));
        FindClose(hFind);
    }
}

// ==========================================
// VAULT VALIDATION (UNCHANGED SECURITY)
// ==========================================
bool validateVault(HANDLE hVault, VaultHeader& header, uint64_t& fileSize) {
    LARGE_INTEGER sz;
    if (!GetFileSizeEx(hVault, &sz)) return false;
    fileSize = sz.QuadPart;

    DWORD br;
    LARGE_INTEGER liPos; liPos.QuadPart = 0; SetFilePointerEx(hVault, liPos, NULL, FILE_BEGIN);
    if (!ReadFile(hVault, &header, sizeof(header), &br, NULL) || br != sizeof(header)) return false;

    if (!constTimeEqual((const BYTE*)header.magic, (const BYTE*)"SVL2", 4)) return false;
    if (header.version != 1) return false;
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
// KEY DERIVATION (UNCHANGED SECURITY)
// ==========================================
bool deriveKey(const std::string& password, const BYTE* salt, BYTE* outEncKey, BYTE* outAuthKey) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA512_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG) != 0x00000000L) return false;
    
    std::string pwdEnc = password + "ENCRYPT";
    std::string pwdAuth = password + "AUTH";
    
    bool s1 = (BCryptDeriveKeyPBKDF2(hAlg, (PUCHAR)pwdEnc.data(), (ULONG)pwdEnc.length(), (PUCHAR)salt, 32, 500000, outEncKey, 32, 0) == 0x00000000L);
    bool s2 = (BCryptDeriveKeyPBKDF2(hAlg, (PUCHAR)pwdAuth.data(), (ULONG)pwdAuth.length(), (PUCHAR)salt, 32, 500000, outAuthKey, 32, 0) == 0x00000000L);
    
    BCryptCloseAlgorithmProvider(hAlg, 0);
    wipeSensitiveData(pwdEnc.data(), pwdEnc.length());
    wipeSensitiveData(pwdAuth.data(), pwdAuth.length());
    return s1 && s2;
}

// ==========================================
// CRYPTO ENGINE (UNCHANGED SECURITY)
// ==========================================
void encryptName(const std::string& name, const BYTE* encKey, const BYTE* authKey, BYTE* outEncrypted, uint32_t& outNameLen, BYTE* outIV, BYTE* outAuthTag) {
    outNameLen = (uint32_t)name.length();
    BCRYPT_ALG_HANDLE hAlg; BCRYPT_KEY_HANDLE hKey;
    BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, (PUCHAR)encKey, 32, 0);
    
    BCryptGenRandom(NULL, outIV, 12, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = outIV;
    authInfo.cbNonce = 12;
    authInfo.pbTag = outAuthTag;
    authInfo.cbTag = 16;
    authInfo.pbAuthData = (PUCHAR)authKey;
    authInfo.cbAuthData = 32;

    DWORD outBytes = 0;
    BYTE inBuf[256] = {0};
    memcpy(inBuf, name.c_str(), name.length());
    BCryptEncrypt(hKey, inBuf, outNameLen, &authInfo, NULL, 0, outEncrypted, 256, &outBytes, 0);
    outNameLen = outBytes;

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    wipeSensitiveData(inBuf, 256);
}

bool decryptName(const BYTE* encryptedName, uint32_t nameLen, const BYTE* encKey, const BYTE* authKey, const BYTE* iv, const BYTE* authTag, std::string& outName) {
    BCRYPT_ALG_HANDLE hAlg; BCRYPT_KEY_HANDLE hKey;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0) != 0x00000000L) return false;
    BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, (PUCHAR)encKey, 32, 0);
    
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = (PUCHAR)iv;
    authInfo.cbNonce = 12;
    authInfo.pbTag = (PUCHAR)authTag;
    authInfo.cbTag = 16;
    authInfo.pbAuthData = (PUCHAR)authKey;
    authInfo.cbAuthData = 32;

    DWORD outBytes = 0;
    BYTE outBuf[256] = {0};
    NTSTATUS status = BCryptDecrypt(hKey, (PUCHAR)encryptedName, nameLen, &authInfo, NULL, 0, outBuf, 256, &outBytes, 0);
    
    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    
    if (status != 0x00000000L) {
        wipeSensitiveData(outBuf, 256);
        return false;
    }
    outName = std::string((char*)outBuf, outBytes);
    wipeSensitiveData(outBuf, 256);
    return true;
}

// ==========================================
// FILE ENCRYPTION (WITH ADDED GUI MESSAGE PUMP)
// ==========================================
bool encryptFile(HANDLE hIn, HANDLE hOutVault, const BYTE* encKey, const BYTE* authKey, FileEntry& entry) {
    BCRYPT_ALG_HANDLE hAlg; BCRYPT_KEY_HANDLE hKey;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0) != 0x00000000L) return false;
    BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, (PUCHAR)encKey, 32, 0);

    BCryptGenRandom(NULL, entry.fileIV, 12, BCRYPT_USE_SYSTEM_PREFERRED_RNG);

    static BYTE inBuffer[CHUNK_SIZE];
    static BYTE outBuffer[CHUNK_SIZE];
    uint64_t totalRead = 0;
    uint32_t chunkIndex = 0;
    bool success = true;

    while (totalRead < entry.originalSize) {
        DWORD toRead = (DWORD)min((uint64_t)CHUNK_SIZE, entry.originalSize - totalRead);
        DWORD bytesRead = 0;
        if (!ReadFile(hIn, inBuffer, toRead, &bytesRead, NULL) || bytesRead == 0) {
            success = false; break;
        }
        totalRead += bytesRead;

        BYTE chunkIV[12];
        memcpy(chunkIV, entry.fileIV, 12);
        uint32_t* counter = (uint32_t*)(chunkIV + 8);
        *counter ^= chunkIndex++;

        BYTE authTag[16];
        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
        BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
        authInfo.pbNonce = chunkIV;
        authInfo.cbNonce = 12;
        authInfo.pbTag = authTag;
        authInfo.cbTag = 16;
        authInfo.pbAuthData = (PUCHAR)authKey;
        authInfo.cbAuthData = 32;

        DWORD outBytes = 0;
        NTSTATUS status = BCryptEncrypt(hKey, inBuffer, bytesRead, &authInfo, NULL, 0, outBuffer, CHUNK_SIZE, &outBytes, 0);
        if (status != 0x00000000L) {
            success = false; break;
        }

        DWORD written = 0;
        if (!WriteFile(hOutVault, outBuffer, outBytes, &written, NULL) || written != outBytes) {
            success = false; break;
        }
        if (!WriteFile(hOutVault, authTag, 16, &written, NULL) || written != 16) {
            success = false; break;
        }

        entry.storedSize += outBytes + 16;
        
        // Progress window update and message pump
        if (g_hProgressWnd) {
            int pct = (int)((totalRead * 100) / entry.originalSize);
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

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return success;
}

// ==========================================
// FILE DECRYPTION (WITH ADDED GUI MESSAGE PUMP)
// ==========================================
bool decryptFile(const FileEntry& entry, HANDLE hVault, const std::string& outPath, const BYTE* encKey, const BYTE* authKey) {
    HANDLE hOut = CreateFileA(outPath.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hOut == INVALID_HANDLE_VALUE) return false;

    LARGE_INTEGER liPos; liPos.QuadPart = (LONGLONG)entry.dataOffset; SetFilePointerEx(hVault, liPos, NULL, FILE_BEGIN);

    BCRYPT_ALG_HANDLE hAlg; BCRYPT_KEY_HANDLE hKey;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0) != 0x00000000L) {
        CloseHandle(hOut); DeleteFileA(outPath.c_str()); return false;
    }
    BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, (PUCHAR)encKey, 32, 0);

    static BYTE inBuffer[CHUNK_SIZE + 16];
    static BYTE outBuffer[CHUNK_SIZE];
    uint64_t totalRead = 0;
    uint32_t chunkIndex = 0;
    bool success = true;

    while (totalRead < entry.storedSize) {
        uint64_t plainRemaining = entry.originalSize - (chunkIndex * (uint64_t)CHUNK_SIZE);
        DWORD plainChunkSize = (DWORD)min((uint64_t)CHUNK_SIZE, plainRemaining);
        DWORD cipherChunkSize = plainChunkSize + 16;
        
        DWORD bytesRead = 0;
        if (!ReadFile(hVault, inBuffer, cipherChunkSize, &bytesRead, NULL) || bytesRead != cipherChunkSize) {
            success = false; break;
        }
        totalRead += bytesRead;

        BYTE chunkIV[12];
        memcpy(chunkIV, entry.fileIV, 12);
        uint32_t* counter = (uint32_t*)(chunkIV + 8);
        *counter ^= chunkIndex++;

        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
        BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
        authInfo.pbNonce = chunkIV;
        authInfo.cbNonce = 12;
        authInfo.pbTag = inBuffer + plainChunkSize;
        authInfo.cbTag = 16;
        authInfo.pbAuthData = (PUCHAR)authKey;
        authInfo.cbAuthData = 32;

        DWORD outBytes = 0;
        NTSTATUS status = BCryptDecrypt(hKey, inBuffer, plainChunkSize, &authInfo, NULL, 0, outBuffer, CHUNK_SIZE, &outBytes, 0);
        if (status != 0x00000000L) {
            success = false; break;
        }

        DWORD written = 0;
        if (plainChunkSize > 0) {
            if (!WriteFile(hOut, outBuffer, outBytes, &written, NULL) || written != outBytes) {
                success = false; break;
            }
        }
        
        MSG msg;
        while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) { TranslateMessage(&msg); DispatchMessage(&msg); }
    }

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    CloseHandle(hOut);

    if (!success) DeleteFileA(outPath.c_str());
    return success;
}

bool verifyEntry(HANDLE hVault, const FileEntry& entry, const BYTE* encKey, const BYTE* authKey) {
    LARGE_INTEGER liPos; liPos.QuadPart = (LONGLONG)entry.dataOffset; SetFilePointerEx(hVault, liPos, NULL, FILE_BEGIN);
    
    BCRYPT_ALG_HANDLE hAlg; BCRYPT_KEY_HANDLE hKey;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0) != 0x00000000L) return false;
    BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, (PUCHAR)encKey, 32, 0);

    static BYTE inBuffer[CHUNK_SIZE + 16];
    static BYTE outBuffer[CHUNK_SIZE];
    uint64_t totalRead = 0;
    uint32_t chunkIndex = 0;
    bool success = true;

    while (totalRead < entry.storedSize) {
        uint64_t plainRemaining = entry.originalSize - (chunkIndex * (uint64_t)CHUNK_SIZE);
        DWORD plainChunkSize = (DWORD)min((uint64_t)CHUNK_SIZE, plainRemaining);
        DWORD cipherChunkSize = plainChunkSize + 16;
        
        DWORD bytesRead = 0;
        if (!ReadFile(hVault, inBuffer, cipherChunkSize, &bytesRead, NULL) || bytesRead != cipherChunkSize) {
            success = false; break;
        }
        totalRead += bytesRead;

        BYTE chunkIV[12];
        memcpy(chunkIV, entry.fileIV, 12);
        uint32_t* counter = (uint32_t*)(chunkIV + 8);
        *counter ^= chunkIndex++;

        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
        BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
        authInfo.pbNonce = chunkIV;
        authInfo.cbNonce = 12;
        authInfo.pbTag = inBuffer + plainChunkSize;
        authInfo.cbTag = 16;
        authInfo.pbAuthData = (PUCHAR)authKey;
        authInfo.cbAuthData = 32;

        DWORD outBytes = 0;
        NTSTATUS status = BCryptDecrypt(hKey, inBuffer, plainChunkSize, &authInfo, NULL, 0, outBuffer, CHUNK_SIZE, &outBytes, 0);
        if (status != 0x00000000L) {
            success = false; break;
        }
        
        MSG msg;
        while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) { TranslateMessage(&msg); DispatchMessage(&msg); }
    }

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return success;
}

// ==========================================
// PASSWORD HANDLING (UNCHANGED SECURITY)
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
    if (!deriveKey(pwd, header.salt, tempEnc, tempAuth)) return false;

    if (header.fileCount > 0) {
        LARGE_INTEGER liPos; liPos.QuadPart = (LONGLONG)header.entriesOffset; SetFilePointerEx(hVault, liPos, NULL, FILE_BEGIN);
        FileEntry e; DWORD br;
        if (!ReadFile(hVault, &e, sizeof(e), &br, NULL) || br != sizeof(e)) {
            wipeSensitiveData(tempEnc, 32); wipeSensitiveData(tempAuth, 32); return false;
        }
        
        std::string name;
        if (!decryptName(e.encryptedName, e.nameLen, tempEnc, tempAuth, e.fileIV, e.nameAuthTag, name)) {
            wipeSensitiveData(tempEnc, 32); wipeSensitiveData(tempAuth, 32); return false;
        }
        memcpy(outEncKey, tempEnc, 32);
        memcpy(outAuthKey, tempAuth, 32);
        wipeSensitiveData(tempEnc, 32); wipeSensitiveData(tempAuth, 32);
        return true;
    } else {
        memcpy(outEncKey, tempEnc, 32);
        memcpy(outAuthKey, tempAuth, 32);
        wipeSensitiveData(tempEnc, 32); wipeSensitiveData(tempAuth, 32);
        return true;
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
    case WM_CREATE:
        CreateWindowExA(0, "EDIT", "", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL, 30, 40, 240, 24, hwnd, (HMENU)1, g_hInst, NULL);
        CreateWindowExA(0, "BUTTON", "OK", WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON, 100, 80, 100, 30, hwnd, (HMENU)2, g_hInst, NULL);
        CenterWindow(hwnd, GetParent(hwnd));
        break;
    case WM_COMMAND:
        if (LOWORD(wParam) == 2) {
            char buf[256] = {0};
            GetDlgItemTextA(hwnd, 1, buf, 256);
            g_InputBoxText = buf;
            DestroyWindow(hwnd);
        }
        break;
    }
    return DefWindowProc(hwnd, msg, wParam, lParam);
}

// --- Result Box Dialog ---
LRESULT CALLBACK ResultBoxProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE: {
        HWND hEdit = CreateWindowExA(0, "EDIT", "", WS_CHILD | WS_VISIBLE | WS_BORDER | WS_VSCROLL | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL, 10, 10, 360, 220, hwnd, (HMENU)1, g_hInst, NULL);
        SendMessageA(hEdit, WM_SETFONT, (WPARAM)g_hFontMono, FALSE);
        SendMessageA(hEdit, WM_SETTEXT, 0, (LPARAM)g_ListResultText.c_str());
        CreateWindowExA(0, "BUTTON", "Close", WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON, 140, 240, 100, 30, hwnd, (HMENU)2, g_hInst, NULL);
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
        } else if (vk == RETURN) {
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

std::string runVKeyboard(HWND hParent, const std::string& title) {
    std::string result = "";
    HWND hDlg = CreateWindowExA(WS_EX_DLGMODALFRAME, "SecureVault2_Kbd", title.c_str(), WS_POPUP | WS_CAPTION | DS_MODALFRAME, 0, 0, 480, 340, hParent, NULL, g_hInst, &result);
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
        uint64_t now; GetSystemTimeAsFileTime((FILETIME*)&now);
        uint64_t elapsedSec = (now - header.lastFailTime) / 10000000ULL;
        if (elapsedSec < waitTime) {
            uint64_t remaining = waitTime - elapsedSec;
            char msg[256];
            snprintf(msg, sizeof(msg), "Lockout active. Try again in %llu seconds.", remaining);
            MessageBoxA(hParent, msg, "Locked", MB_ICONWARNING);
            return false;
        }
    }

    std::string pwd = runVKeyboard(hParent, "Enter Vault Password");
    if (pwd.empty()) return false;

    bool success = verifyPassword(hVault, header, pwd, outEncKey, outAuthKey);
    wipeSensitiveData(pwd.data(), pwd.length());

    if (!success) {
        header.failedAttempts++;
        GetSystemTimeAsFileTime((FILETIME*)&header.lastFailTime);
        LARGE_INTEGER liPos; liPos.QuadPart = 0; SetFilePointerEx(hVault, liPos, NULL, FILE_BEGIN);
        DWORD bw; WriteFile(hVault, &header, sizeof(header), &bw, NULL);
        MessageBoxA(hParent, "Wrong password — vault locked", "Error", MB_ICONERROR);
        return false;
    } else {
        if (header.failedAttempts > 0) {
            header.failedAttempts = 0;
            header.lastFailTime = 0;
            LARGE_INTEGER liPos; liPos.QuadPart = 0; SetFilePointerEx(hVault, liPos, NULL, FILE_BEGIN);
            DWORD bw; WriteFile(hVault, &header, sizeof(header), &bw, NULL);
        }
        return true;
    }
}

void CreateVaultFlow() {
    char szFile[MAX_PATH] = {0};
    OPENFILENAMEA ofn = {0};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = g_hMainWnd;
    ofn.lpstrFile = szFile;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrFilter = "Vault Files (*.vault)\0*.vault\0All Files (*.*)\0*.*\0";
    ofn.lpstrDefExt = "vault";
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_OVERWRITEPROMPT;
    
    if (GetSaveFileNameA(&ofn)) {
        std::string pwd, err;
        while (true) {
            pwd = runVKeyboard(g_hMainWnd, "Set Password");
            if (pwd.empty()) return;
            if (validatePassword(pwd, err)) break;
            MessageBoxA(g_hMainWnd, err.c_str(), "Invalid Password", MB_ICONERROR);
        }

        VaultHeader header = {0};
        memcpy(header.magic, "SVL2", 4);
        header.version = 1;
        header.iterations = 500000;
        BCryptGenRandom(NULL, header.salt, 32, BCRYPT_USE_SYSTEM_PREFERRED_RNG);

        header.fileCount = 0;
        header.failedAttempts = 0;
        header.lastFailTime = 0;
        header.dataOffset = sizeof(VaultHeader);
        header.entriesOffset = sizeof(VaultHeader);

        HANDLE hVault = CreateFileA(szFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hVault == INVALID_HANDLE_VALUE) {
            MessageBoxA(g_hMainWnd, "Out of disk space or write error", "Error", MB_ICONERROR);
            return;
        }
        
        DWORD bw; 
        if (!WriteFile(hVault, &header, sizeof(header), &bw, NULL)) {
            MessageBoxA(g_hMainWnd, "Out of disk space or write error", "Error", MB_ICONERROR);
            CloseHandle(hVault); return;
        }

        CloseHandle(hVault);
        wipeSensitiveData(pwd.data(), pwd.length());
        std::string st = "Vault created: " + std::string(szFile);
        SetStatus(st.c_str());
    }
}

void LockFileFlow() {
    char szSrcFile[MAX_PATH] = {0};
    OPENFILENAMEA ofn1 = {0};
    ofn1.lStructSize = sizeof(ofn1);
    ofn1.hwndOwner = g_hMainWnd;
    ofn1.lpstrFile = szSrcFile;
    ofn1.nMaxFile = MAX_PATH;
    ofn1.lpstrTitle = "Select File to Lock";
    ofn1.lpstrFilter = "All Files (*.*)\0*.*\0";
    ofn1.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
    if (!GetOpenFileNameA(&ofn1)) return;

    char szVaultFile[MAX_PATH] = {0};
    OPENFILENAMEA ofn2 = {0};
    ofn2.lStructSize = sizeof(ofn2);
    ofn2.hwndOwner = g_hMainWnd;
    ofn2.lpstrFile = szVaultFile;
    ofn2.nMaxFile = MAX_PATH;
    ofn2.lpstrTitle = "Select Vault";
    ofn2.lpstrFilter = "Vault Files (*.vault)\0*.vault\0All Files (*.*)\0*.*\0";
    ofn2.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
    if (!GetOpenFileNameA(&ofn2)) return;

    HANDLE hIn = CreateFileA(szSrcFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (hIn == INVALID_HANDLE_VALUE) { MessageBoxA(g_hMainWnd, "File missing or cannot be opened", "Error", MB_ICONERROR); return; }
    
    LARGE_INTEGER sz; GetFileSizeEx(hIn, &sz);
    if (sz.QuadPart == 0) { MessageBoxA(g_hMainWnd, "Cannot lock empty files.", "Error", MB_ICONERROR); CloseHandle(hIn); return; }

    HANDLE hVault = CreateFileA(szVaultFile, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hVault == INVALID_HANDLE_VALUE) { MessageBoxA(g_hMainWnd, "Vault file missing or cannot be opened", "Error", MB_ICONERROR); CloseHandle(hIn); return; }

    uint64_t vSize = 0;
    VaultHeader header;
    if (!validateVault(hVault, header, vSize)) {
        MessageBoxA(g_hMainWnd, "Invalid or corrupted vault file", "Error", MB_ICONERROR);
        CloseHandle(hVault); CloseHandle(hIn); return;
    }

    BYTE encKey[32], authKey[32];
    if (!guiAuthenticate(g_hMainWnd, hVault, header, encKey, authKey)) {
        CloseHandle(hVault); CloseHandle(hIn); return;
    }

    char tempPath[MAX_PATH];
    char tempDir[MAX_PATH];
    GetTempPathA(MAX_PATH, tempDir);
    GetTempFileNameA(tempDir, "SVL", 0, tempPath);
    
    HANDLE hTemp = CreateFileA(tempPath, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hTemp == INVALID_HANDLE_VALUE) {
        MessageBoxA(g_hMainWnd, "Out of disk space or write error", "Error", MB_ICONERROR);
        wipeSensitiveData(encKey, 32); wipeSensitiveData(authKey, 32);
        CloseHandle(hVault); CloseHandle(hIn); return;
    }

    LARGE_INTEGER liPos1; liPos1.QuadPart = 0; SetFilePointerEx(hVault, liPos1, NULL, FILE_BEGIN);
    uint64_t toCopy = header.entriesOffset;
    uint64_t copied = 0;
    static BYTE copyBuf[CHUNK_SIZE];
    bool copySuccess = true;
    
    while (copied < toCopy) {
        DWORD chunk = (DWORD)min((uint64_t)CHUNK_SIZE, toCopy - copied);
        DWORD br, bw;
        if (!ReadFile(hVault, copyBuf, chunk, &br, NULL) || br == 0) { copySuccess = false; break; }
        if (!WriteFile(hTemp, copyBuf, br, &bw, NULL) || bw != br) { copySuccess = false; break; }
        copied += br;
    }

    if (!copySuccess) {
        MessageBoxA(g_hMainWnd, "Out of disk space or write error", "Error", MB_ICONERROR);
        CloseHandle(hTemp); DeleteFileA(tempPath); wipeSensitiveData(encKey, 32); wipeSensitiveData(authKey, 32);
        CloseHandle(hVault); CloseHandle(hIn); return;
    }

    FileEntry newEntry = {0};
    std::string fileStr = szSrcFile;
    size_t lastSlash = fileStr.find_last_of("/\\");
    std::string baseName = (lastSlash == std::string::npos) ? fileStr : fileStr.substr(lastSlash + 1);
    
    encryptName(baseName, encKey, authKey, newEntry.encryptedName, newEntry.nameLen, newEntry.fileIV, newEntry.nameAuthTag);
    newEntry.dataOffset = header.entriesOffset;
    newEntry.originalSize = sz.QuadPart;
    newEntry.storedSize = 0;

    g_hProgressWnd = CreateWindowExA(0, "SecureVault2_Progress", "", WS_POPUP | WS_BORDER, 0, 0, 400, 120, g_hMainWnd, NULL, g_hInst, NULL);
    CenterWindow(g_hProgressWnd, g_hMainWnd);
    ShowWindow(g_hProgressWnd, SW_SHOW);
    g_ProgressPct = 0;

    bool encOK = encryptFile(hIn, hTemp, encKey, authKey, newEntry);
    
    DestroyWindow(g_hProgressWnd);
    g_hProgressWnd = NULL;

    if (!encOK || !verifyEntry(hTemp, newEntry, encKey, authKey)) {
        MessageBoxA(g_hMainWnd, "Encryption failed — vault unchanged", "Error", MB_ICONERROR);
        CloseHandle(hTemp); DeleteFileA(tempPath); wipeSensitiveData(encKey, 32); wipeSensitiveData(authKey, 32);
        CloseHandle(hVault); CloseHandle(hIn); return;
    }

    LARGE_INTEGER pos;
    LARGE_INTEGER liPos2; liPos2.QuadPart = 0; SetFilePointerEx(hTemp, liPos2, &pos, FILE_CURRENT);

    DWORD bw;
    LARGE_INTEGER liPos3; liPos3.QuadPart = (LONGLONG)header.entriesOffset; SetFilePointerEx(hVault, liPos3, NULL, FILE_BEGIN);
    for (uint32_t i = 0; i < header.fileCount; ++i) {
        FileEntry e; DWORD br;
        if (ReadFile(hVault, &e, sizeof(e), &br, NULL) && br == sizeof(e)) {
            if (!WriteFile(hTemp, &e, sizeof(e), &bw, NULL)) { copySuccess = false; break; }
        }
    }

    header.entriesOffset = pos.QuadPart;
    header.fileCount++;
    if (!WriteFile(hTemp, &newEntry, sizeof(newEntry), &bw, NULL)) copySuccess = false;

    LARGE_INTEGER liPos4; liPos4.QuadPart = 0; SetFilePointerEx(hTemp, liPos4, NULL, FILE_BEGIN);
    if (!WriteFile(hTemp, &header, sizeof(header), &bw, NULL)) copySuccess = false;

    if (!copySuccess) {
        MessageBoxA(g_hMainWnd, "Out of disk space or write error", "Error", MB_ICONERROR);
        CloseHandle(hTemp); DeleteFileA(tempPath); wipeSensitiveData(encKey, 32); wipeSensitiveData(authKey, 32);
        CloseHandle(hVault); CloseHandle(hIn); return;
    }

    CloseHandle(hTemp); CloseHandle(hVault); CloseHandle(hIn);

    if (!MoveFileExA(tempPath, szVaultFile, MOVEFILE_REPLACE_EXISTING)) {
        MessageBoxA(g_hMainWnd, "Out of disk space or write error", "Error", MB_ICONERROR);
        DeleteFileA(tempPath); wipeSensitiveData(encKey, 32); wipeSensitiveData(authKey, 32); return;
    }
    
    wipeSensitiveData(encKey, 32); wipeSensitiveData(authKey, 32);

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

void UnlockFileFlow() {
    char szVaultFile[MAX_PATH] = {0};
    OPENFILENAMEA ofn = {0};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = g_hMainWnd;
    ofn.lpstrFile = szVaultFile;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrTitle = "Select Vault";
    ofn.lpstrFilter = "Vault Files (*.vault)\0*.vault\0All Files (*.*)\0*.*\0";
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
    if (!GetOpenFileNameA(&ofn)) return;

    g_InputBoxText = "";
    HWND hInput = CreateWindowExA(WS_EX_DLGMODALFRAME, "SecureVault2_Input", "Enter filename to extract", WS_POPUP | WS_CAPTION | DS_MODALFRAME, 0, 0, 300, 160, g_hMainWnd, NULL, g_hInst, NULL);
    EnableWindow(g_hMainWnd, FALSE);
    ShowWindow(hInput, SW_SHOW);
    MSG msg;
    while (IsWindow(hInput) && GetMessage(&msg, NULL, 0, 0)) { TranslateMessage(&msg); DispatchMessage(&msg); }
    EnableWindow(g_hMainWnd, TRUE);
    SetForegroundWindow(g_hMainWnd);

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
    char szVaultFile[MAX_PATH] = {0};
    OPENFILENAMEA ofn = {0};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = g_hMainWnd;
    ofn.lpstrFile = szVaultFile;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrTitle = "Select Vault";
    ofn.lpstrFilter = "Vault Files (*.vault)\0*.vault\0All Files (*.*)\0*.*\0";
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
    if (!GetOpenFileNameA(&ofn)) return;

    HANDLE hVault = CreateFileA(szVaultFile, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hVault == INVALID_HANDLE_VALUE) { MessageBoxA(g_hMainWnd, "Vault file missing or cannot be opened", "Error", MB_ICONERROR); return; }

    uint64_t vSize = 0;
    VaultHeader header;
    if (!validateVault(hVault, header, vSize)) {
        MessageBoxA(g_hMainWnd, "Invalid or corrupted vault file", "Error", MB_ICONERROR); CloseHandle(hVault); return;
    }

    BYTE encKey[32], authKey[32];
    if (!guiAuthenticate(g_hMainWnd, hVault, header, encKey, authKey)) { CloseHandle(hVault); return; }

    std::string res = "Files in vault:\r\n-----------------------\r\n";
    uint32_t okCount = 0, corruptCount = 0;

    for (uint32_t i = 0; i < header.fileCount; ++i) {
        LARGE_INTEGER liPos; liPos.QuadPart = (LONGLONG)header.entriesOffset + i * (LONGLONG)sizeof(FileEntry); SetFilePointerEx(hVault, liPos, NULL, FILE_BEGIN);
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

        CreateWindowExA(0, "BUTTON", "Create Vault", WS_CHILD|WS_VISIBLE|BS_OWNERDRAW, 160, 80, 200, 44, hwnd, (HMENU)101, g_hInst, NULL);
        CreateWindowExA(0, "BUTTON", "Lock File", WS_CHILD|WS_VISIBLE|BS_OWNERDRAW, 160, 140, 200, 44, hwnd, (HMENU)102, g_hInst, NULL);
        CreateWindowExA(0, "BUTTON", "Unlock File", WS_CHILD|WS_VISIBLE|BS_OWNERDRAW, 160, 200, 200, 44, hwnd, (HMENU)103, g_hInst, NULL);
        CreateWindowExA(0, "BUTTON", "List & Verify", WS_CHILD|WS_VISIBLE|BS_OWNERDRAW, 160, 260, 200, 44, hwnd, (HMENU)104, g_hInst, NULL);
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
    RegisterClassA(&wc);

    wc.lpfnWndProc = KeyboardProc;
    wc.lpszClassName = "SecureVault2_Kbd";
    RegisterClassA(&wc);

    wc.lpfnWndProc = ProgressProc;
    wc.lpszClassName = "SecureVault2_Progress";
    RegisterClassA(&wc);

    wc.lpfnWndProc = InputBoxProc;
    wc.lpszClassName = "SecureVault2_Input";
    RegisterClassA(&wc);

    wc.lpfnWndProc = ResultBoxProc;
    wc.lpszClassName = "SecureVault2_Result";
    RegisterClassA(&wc);

    RECT wr = {0, 0, 520, 420};
    AdjustWindowRectEx(&wr, WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX, FALSE, 0);

    g_hMainWnd = CreateWindowExA(0, "SecureVault2_Main", "SecureVault2 " VAULT_VERSION, 
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX, 
        CW_USEDEFAULT, CW_USEDEFAULT, wr.right - wr.left, wr.bottom - wr.top, 
        NULL, NULL, hInstance, NULL);

    ShowWindow(g_hMainWnd, nCmdShow);
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
