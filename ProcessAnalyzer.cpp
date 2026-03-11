#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <shlwapi.h>
#include <map>
#include <algorithm>
#include "ProcessAnalyzer.h"

#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "Shlwapi.lib")

static ULONGLONG g_prevSysTime = 0;
static ULONGLONG g_prevKernTime = 0;
static ULONGLONG g_prevUserTime = 0;

// 스레드별 이전 시간을 저장할 전역/정적 변수 (TID, 이전 시간)
static std::map<DWORD, ULONGLONG> g_prevThreadTimes;

void ProcessAnalyzer::ResetHistory() {
    g_prevSysTime = 0;
    g_prevKernTime = 0;
    g_prevUserTime = 0;
}

void ProcessAnalyzer::CaptureThreadContext(HANDLE hProcess, DWORD tid, ThreadDetail& outThread) {
    // 1. 스레드 권한 획득
    HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION | THREAD_SUSPEND_RESUME, FALSE, tid);
    if (!hThread) return;

    // (Start Address) 정보 수집
    DWORD64 startAddr = 0;
    if (SUCCEEDED(GetThreadInformation(hThread, (THREAD_INFORMATION_CLASS)9, &startAddr, sizeof(startAddr)))) {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQueryEx(hProcess, (LPCVOID)startAddr, &mbi, sizeof(mbi))) {
            WCHAR szMod[MAX_PATH];
            if (GetModuleFileNameExW(hProcess, (HMODULE)mbi.AllocationBase, szMod, MAX_PATH)) {
                outThread.startModule = PathFindFileNameW(szMod);
                outThread.startOffset = startAddr - (DWORD64)mbi.AllocationBase;
            } else {
                outThread.startModule = L"[Unknown]";
                outThread.startOffset = 0;
            }
        }
    }

    if (SuspendThread(hThread) != (DWORD)-1) {
        CONTEXT ctx;
        ctx.ContextFlags = CONTEXT_CONTROL;

        if (GetThreadContext(hThread, &ctx)) {
#ifdef _M_X64
            outThread.rip = ctx.Rip;
#else
            outThread.rip = ctx.Eip;
#endif

            // 2. 타겟 프로세스의 메모리 정보 쿼리
            MEMORY_BASIC_INFORMATION mbi;
            if (VirtualQueryEx(hProcess, (LPCVOID)outThread.rip, &mbi, sizeof(mbi))) {
                // mbi.AllocationBase가 해당 모듈(DLL)의 시작 주소입니다.
                WCHAR szModPath[MAX_PATH]; 

                if (GetModuleFileNameExW(hProcess, (HMODULE)mbi.AllocationBase, szModPath, MAX_PATH)) {
                    outThread.moduleName = PathFindFileNameW(szModPath);
                    outThread.relativeOffset = outThread.rip - (DWORD64)mbi.AllocationBase;
                } else {
                    // 모듈 이름이 안 나오면 시스템 영역이거나 JIT 컴파일 영역
                    outThread.moduleName = L"[Memory Region]";
                    outThread.relativeOffset = 0;
                }
            }
        }
        ResumeThread(hThread);
    }
    CloseHandle(hThread);
}

void ProcessAnalyzer::GetUpdate(DWORD pid, ProcessDeepDetail* d) {
    if (!d) return;

    SYSTEM_INFO si;
    GetSystemInfo(&si);
    d->coreCount = si.dwNumberOfProcessors;
    d->pid = pid;

    HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!h) return;

    // 1. 핸들 및 시스템 정보 수집
    DWORD dwHandleCount = 0;
    if (GetProcessHandleCount(h, &dwHandleCount)) d->handleCount = dwHandleCount;

    PERFORMANCE_INFORMATION perfInfo;
    perfInfo.cb = sizeof(PERFORMANCE_INFORMATION);
    if (GetPerformanceInfo(&perfInfo, sizeof(perfInfo))) {
        d->systemTotalHandles = (DWORD)perfInfo.HandleCount;
        d->systemTotalThreads = (DWORD)perfInfo.ThreadCount;
    }

    // 2. 메모리 수집
    PROCESS_MEMORY_COUNTERS_EX pmc;
    if (GetProcessMemoryInfo(h, (PROCESS_MEMORY_COUNTERS*)&pmc, sizeof(pmc))) {
        d->workingSet = pmc.WorkingSetSize;
        d->privateBytes = pmc.PrivateUsage;
        d->peakWorkingSet = pmc.PeakWorkingSetSize;
        d->pageFaults = pmc.PageFaultCount;
        d->virtualSize = pmc.PagefileUsage;
    }

    // 3. CPU 릴레이 계산
    double sysDiff = 0.0;
    FILETIME sI, sK, sU, pC, pE, pK, pU;
    if (GetSystemTimes(&sI, &sK, &sU) && GetProcessTimes(h, &pC, &pE, &pK, &pU)) {
        ULARGE_INTEGER sk, su, pk, pu;
        sk.LowPart = sK.dwLowDateTime; sk.HighPart = sK.dwHighDateTime;
        su.LowPart = sU.dwLowDateTime; su.HighPart = sU.dwHighDateTime;
        pk.LowPart = pK.dwLowDateTime; pk.HighPart = pK.dwHighDateTime;
        pu.LowPart = pU.dwLowDateTime; pu.HighPart = pU.dwHighDateTime;

        ULONGLONG curSys = sk.QuadPart + su.QuadPart;
        if (g_prevSysTime > 0 && curSys > g_prevSysTime) {
            sysDiff = (double)(curSys - g_prevSysTime);
            double multiplier = 100.0; 

            d->kernelCpu = ((double)(pk.QuadPart - g_prevKernTime) * multiplier) / sysDiff;
            d->userCpu   = ((double)(pu.QuadPart - g_prevUserTime) * multiplier) / sysDiff;
            d->totalCpu  = d->kernelCpu + d->userCpu;           
        }
        g_prevSysTime = curSys;
        g_prevKernTime = pk.QuadPart;
        g_prevUserTime = pu.QuadPart;
    }

    // 4. 자원 및 스레드 수집
    d->threads.clear();
    d->threadCount = 0;

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        THREADENTRY32 te;
        te.dwSize = sizeof(te);
        if (Thread32First(hSnap, &te)) {
            do {
                if (te.th32OwnerProcessID == pid) {
                    d->threadCount++;
                    ThreadDetail td = {};
                    td.tid = te.th32ThreadID;
                    td.priority = te.tpBasePri;

                    // --- 스레드별 CPU 계산 로직 ---
                    HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, td.tid);
                    if (hThread) {
                        FILETIME ct, et, kt, ut;
                        if (GetThreadTimes(hThread, &ct, &et, &kt, &ut)) {
                            ULARGE_INTEGER tK, tU;
                            tK.LowPart = kt.dwLowDateTime; tK.HighPart = kt.dwHighDateTime;
                            tU.LowPart = ut.dwLowDateTime; tU.HighPart = ut.dwHighDateTime;
                            ULONGLONG curT = tK.QuadPart + tU.QuadPart;

                            if (sysDiff > 0 && g_prevThreadTimes.count(td.tid)) {
                                // 현재 시간 - 이전 시간 차이를 sysDiff로 나눔
                                td.cpuUsage = ((double)(curT - g_prevThreadTimes[td.tid]) * 100.0) / sysDiff;
                            }
                            g_prevThreadTimes[td.tid] = curT;
                        }
                        CloseHandle(hThread);
                    }

                    CaptureThreadContext(h, td.tid, td); 
                    d->threads.push_back(td);
                }
            } while (Thread32Next(hSnap, &te));
        }
        CloseHandle(hSnap);
    }

    std::sort(d->threads.begin(), d->threads.end(), [](const ThreadDetail& a, const ThreadDetail& b) {
    // CPU 점유율이 높은 순서(내림차순)로 정렬
    return a.cpuUsage > b.cpuUsage; 
    });

    d->priority = GetPriorityClass(h);
    wchar_t path[MAX_PATH];
    DWORD sz = MAX_PATH;
    if (QueryFullProcessImageNameW(h, 0, path, &sz)) d->exePath = path;

    CloseHandle(h);
}

std::wstring ProcessAnalyzer::FormatBytes(size_t bytes) {
    if (bytes == 0) return L"0 B";
    const wchar_t* units[] = { L"B", L"KB", L"MB", L"GB" };
    double size = (double)bytes;
    int i = 0;
    while (size >= 1024 && i < 3) {
        size /= 1024;
        i++;
    }
    wchar_t buf[64];
    // B 단위는 정수, 그 외에는 소수점 2자리 표시
    if (i == 0) swprintf_s(buf, L"%.0f %s", size, units[i]);
    else swprintf_s(buf, L"%.2f %s", size, units[i]);
    return buf;
}

std::wstring ProcessAnalyzer::GetPriorityStr(DWORD priority) {
    switch (priority) {
        case REALTIME_PRIORITY_CLASS: return L"Realtime";
        case HIGH_PRIORITY_CLASS:     return L"High";
        case NORMAL_PRIORITY_CLASS:   return L"Normal";
        case IDLE_PRIORITY_CLASS:     return L"Idle";
        default: return L"Others";
    }
}