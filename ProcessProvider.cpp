#include "ProcessProvider.h"
#include <psapi.h>
#include <tlhelp32.h>
#include <map>
#include <algorithm>
#include <winver.h>
#include <winsvc.h>

#pragma comment(lib, "Version.lib")

// --- [PID로 서비스 이름 찾기] ---
std::wstring GetServiceNameFromPID(DWORD pid) {
    static SC_HANDLE hSCM = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE);
    if (!hSCM) return L"";

    DWORD bytesNeeded = 0;
    DWORD servicesReturned = 0;
    DWORD resumeHandle = 0;

    // 1. 필요한 버퍼 크기 먼저 파악
    EnumServicesStatusExW(hSCM, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_ACTIVE,
        NULL, 0, &bytesNeeded, &servicesReturned, &resumeHandle, NULL);

    if (GetLastError() != ERROR_MORE_DATA) return L"";

    std::vector<BYTE> buffer(bytesNeeded);
    if (EnumServicesStatusExW(hSCM, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_ACTIVE,
        buffer.data(), bytesNeeded, &bytesNeeded, &servicesReturned, &resumeHandle, NULL)) {
        
        LPENUM_SERVICE_STATUS_PROCESSW services = (LPENUM_SERVICE_STATUS_PROCESSW)buffer.data();
        for (DWORD i = 0; i < servicesReturned; i++) {
            if (services[i].ServiceStatusProcess.dwProcessId == pid) {
                return services[i].lpDisplayName;
            }
        }
    }
    return L"";
}

// --- [헬퍼 함수들] ---
std::wstring ProcessProvider::GetFileDescription(const std::wstring& filePath) {
    DWORD dummy;
    DWORD size = GetFileVersionInfoSizeW(filePath.c_str(), &dummy);
    if (size == 0) return L"";
    std::vector<BYTE> data(size);
    if (!GetFileVersionInfoW(filePath.c_str(), 0, size, &data[0])) return L"";
    struct LANGANDCODEPAGE { WORD wLanguage; WORD wCodePage; } *lpTranslate;
    UINT cbTranslate;
    if (VerQueryValueW(&data[0], L"\\VarFileInfo\\Translation", (LPVOID*)&lpTranslate, &cbTranslate)) {
        wchar_t subBlock[256];
        swprintf_s(subBlock, L"\\StringFileInfo\\%04x%04x\\FileDescription", 
                   lpTranslate[0].wLanguage, lpTranslate[0].wCodePage);
        wchar_t* description = nullptr;
        UINT len = 0;
        if (VerQueryValueW(&data[0], subBlock, (LPVOID*)&description, &len)) return description;
    }
    return L"";
}

BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam) {
    SearchData* data = (SearchData*)lParam;
    DWORD processId = 0;
    GetWindowThreadProcessId(hwnd, &processId);
    if (processId == data->pid) {
        wchar_t buf[512];
        if (GetWindowTextW(hwnd, buf, 512) > 0) {
            data->title = buf;
            return FALSE;
        }
    }
    return TRUE;
}

double ToDouble(FILETIME ft) {
    ULARGE_INTEGER ul;
    ul.LowPart = ft.dwLowDateTime; ul.HighPart = ft.dwHighDateTime;
    return (double)ul.QuadPart;
}

std::wstring ProcessProvider::GetWindowTitle(DWORD pid) {
    SearchData data = { pid, L"" };
    EnumWindows(EnumWindowsProc, (LPARAM)&data);
    return data.title.empty() ? L"-" : data.title;
}

size_t ProcessProvider::GetMemoryUsage(HANDLE hProcess) {
    PROCESS_MEMORY_COUNTERS pmc;
    if (GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc))) return pmc.WorkingSetSize / 1024 / 1024;
    return 0;
}

double ProcessProvider::GetProcessRawTime(HANDLE hProcess) {
    FILETIME cT, eT, kT, uT;
    if (GetProcessTimes(hProcess, &cT, &eT, &kT, &uT)) return ToDouble(kT) + ToDouble(uT);
    return 0.0;
}

// --- [핵심 메서드] ---
std::vector<ProcessStats> ProcessProvider::GetAllProcesses() {
    std::vector<ProcessStats> results;
    std::map<DWORD, double> startTimesMap;

    FILETIME sI1, sK1, sU1;
    GetSystemTimes(&sI1, &sK1, &sU1);
    double systemStart = ToDouble(sK1) + ToDouble(sU1);

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return results;

    PROCESSENTRY32W pe = { sizeof(pe) };
    if (Process32FirstW(hSnapshot, &pe)) {
        do {
            HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
            if (h) {
                startTimesMap[pe.th32ProcessID] = GetProcessRawTime(h);
                CloseHandle(h);
            }
        } while (Process32NextW(hSnapshot, &pe));
    }

    Sleep(1000);

    FILETIME sI2, sK2, sU2;
    GetSystemTimes(&sI2, &sK2, &sU2);
    double systemEnd = ToDouble(sK2) + ToDouble(sU2);
    double systemDiff = systemEnd - systemStart;

    if (Process32FirstW(hSnapshot, &pe)) {
        do {
            double cpuUsage = 0.0;
            size_t memory = 0;
            std::wstring windowTitle = GetWindowTitle(pe.th32ProcessID);
            std::wstring description = L"";
            std::wstring serviceName = L"";

            HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
            if (h) {
                memory = GetMemoryUsage(h);
                double endTime = GetProcessRawTime(h);
                if (startTimesMap.count(pe.th32ProcessID) && systemDiff > 0) {
                    cpuUsage = ((endTime - startTimesMap[pe.th32ProcessID]) / systemDiff) * 100.0;
                }
                
                wchar_t exePath[MAX_PATH];
                DWORD pathSize = MAX_PATH;
                if (QueryFullProcessImageNameW(h, 0, exePath, &pathSize)) {
                    description = GetFileDescription(exePath);
                }
                CloseHandle(h);
            }

            // 서비스 이름 조회 (창 제목이 없을 때 svchost 같은 것들을 위해)
            if (windowTitle == L"-") {
                serviceName = GetServiceNameFromPID(pe.th32ProcessID);
            }

            // --- [최종 이름 결정 우선순위] ---
            std::wstring finalTitle;
            if (windowTitle != L"-") {
                finalTitle = windowTitle; // 1. 실제 창 제목
            } else if (!serviceName.empty()) {
                finalTitle = serviceName; // 2. 서비스 표시 이름
            } else if (!description.empty()) {
                finalTitle = description; // 3. 파일 설명
            } else {
                // 4. 마지막 보루: 파일명에서 확장자 떼고 대문자로
                std::wstring tmp = pe.szExeFile;
                size_t dot = tmp.find_last_of(L'.');
                if (dot != std::wstring::npos) tmp = tmp.substr(0, dot);
                std::transform(tmp.begin(), tmp.end(), tmp.begin(), ::toupper);
                finalTitle = tmp;
            }

            results.push_back({ 
                pe.th32ProcessID, 
                pe.szExeFile, 
                finalTitle, 
                memory, 
                cpuUsage, 
                1 
            });
        } while (Process32NextW(hSnapshot, &pe));
    }
    CloseHandle(hSnapshot);
    return results;
}