#include <iostream>
#include <windows.h>
#include <tlhelp32.h>

DWORD GetProcessID(const wchar_t *processName) {
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (Process32First(snapshot, &entry)) {
        while (Process32Next(snapshot, &entry)) {
            if (wcscmp(entry.szExeFile, processName) == 0) {
                CloseHandle(snapshot);
                return entry.th32ProcessID;
            }
        }
    }
    CloseHandle(snapshot);
    return 0;
}

bool SuspendProcessThreads(HANDLE processHandle) {
    DWORD processID = GetProcessId(processHandle);

    HANDLE threadSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    THREADENTRY32 threadEntry;
    threadEntry.dwSize = sizeof(THREADENTRY32);

    bool success = false;
    Thread32First(threadSnapshot, &threadEntry);
    do {
        if (threadEntry.th32OwnerProcessID == processID) {
            HANDLE threadHandle = OpenThread(THREAD_ALL_ACCESS, FALSE, threadEntry.th32ThreadID);
            if (!threadHandle) {
                continue;
            }
            if (SuspendThread(threadHandle)) {
                success = true;
            }
            CloseHandle(threadHandle);
        }
    } while (Thread32Next(threadSnapshot, &threadEntry));

    CloseHandle(threadSnapshot);
    return success;
}

template<typename F>
void EnumeratePageRegionsInfo(HANDLE processHandle, F processPageRegionInfo) {
    MEMORY_BASIC_INFORMATION pageRegion;
    LPVOID queryAddress = NULL;
    bool success = false;
    while (VirtualQueryEx(processHandle, queryAddress, &pageRegion, sizeof(MEMORY_BASIC_INFORMATION))) {
        processPageRegionInfo(pageRegion);
        queryAddress = (void*)((uint64_t)queryAddress + (uint64_t)pageRegion.RegionSize);
        success = true;
    }
    if (!success) {
        std::cout << "Failed to query memory information: " << GetLastError() << std::endl;
    }
}

template<typename F, typename G>
void EnumeratePageRegionsMemory(HANDLE processHandle, F pageRegionPredicate, G processPageRegionMemory) {
    EnumeratePageRegionsInfo(processHandle, [processHandle, pageRegionPredicate, processPageRegionMemory](MEMORY_BASIC_INFORMATION region) {
        if (!pageRegionPredicate(region)) {
            return;
        }
        void* memory = malloc(region.RegionSize);
        if (!memory) {
            std::cout << "Failed to read process memory: malloc failed size=" << region.RegionSize << std::endl;
            return;
        }
        if (!ReadProcessMemory(processHandle, region.BaseAddress, memory, region.RegionSize, NULL)) {
            std::cout << "Failed to read process memory: " << GetLastError() << std::endl;
            free(memory);
            return;
        }
        processPageRegionMemory(memory, region.RegionSize);
        free(memory);
    });
}

// https://stackoverflow.com/a/2188951/16397243
void* memmem(const void* haystack, size_t hlen, const void* needle, size_t nlen) {
    int needle_first;
    const uint8_t* p = (const uint8_t*)haystack;
    size_t plen = hlen;

    if (!nlen)
        return NULL;

    needle_first = *(uint8_t *)needle;

    while (plen >= nlen && (p = (const uint8_t*)memchr(p, needle_first, plen - nlen + 1))) {
        if (!memcmp(p, needle, nlen))
            return (void*)p;

        p++;
        plen = hlen - (p - (const uint8_t*)haystack);
    }
    return NULL;
}

template<typename F>
void EnumerateMemoryMatches(const void* haystack, size_t hlen, const void* needle, size_t nlen, F processMatch) {
    const uint8_t* match;
    do {
        match = (uint8_t *)memmem(haystack, hlen, needle, nlen);
        if (match) {
            processMatch((void *)match);
            size_t matchOffset = match - (uint8_t *)haystack;
            haystack = match + nlen;
            hlen -= matchOffset + nlen;
        }
    } while (match && hlen >= nlen);
}

bool isPageRegionReadable(MEMORY_BASIC_INFORMATION region) {
    return region.Protect == PAGE_READWRITE || 
        region.Protect == PAGE_EXECUTE_READWRITE ||
        region.Protect == PAGE_READONLY;
}

int wmain(int argc, wchar_t* argv[], wchar_t* envp[]) {
    if (argc < 3) {
        std::cout << "Usage: <process name> <string to query process memory for>" << std::endl;
        return 1;
    }
    wchar_t* processName = argv[1];
    wchar_t* query = argv[2];

    DWORD processID = GetProcessID(processName);
    if (!processID) {
        std::cout << "Failed to find process name=" << processName << std::endl;
        return 1;
    }
    HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
    if (!processHandle) {
        std::cout << "Failed to obtain process handle" << std::endl;
        return 1;
    }
    if (!SuspendProcessThreads(processHandle)) {
        std::cout << "Failed to suspend process threads" << std::endl;
        return 1;
    }

    EnumeratePageRegionsMemory(processHandle, isPageRegionReadable, [query](void* memory, size_t length) {
        // Search for the wide-char version of the query
        EnumerateMemoryMatches(memory, length, (void *)query, wcslen(query), [](void *match) {
            std::wcout << "Found match: " << (wchar_t *)match <<  std::endl;
        });
        // Search for the multibyte version of the query, if it's convertable to multibyte.
        char processNameMB[256] = { 0 };
        if (wcstombs_s(NULL, processNameMB, query, sizeof(processNameMB) - 1)) {
            return;
        }
        EnumerateMemoryMatches(memory, length, (void *)processNameMB, strlen(processNameMB), [](void *match) {
            std::cout << "Found match: " << (char *)match << std::endl;
        });
    });
    return 0;
}