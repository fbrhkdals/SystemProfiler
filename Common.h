#pragma once
#include <string>
#include <vector>
#include <windows.h>

// 정렬 기준을 정의하는 열거형
enum class SortBy { MEMORY, CPU };

// 프로세스 정보를 담는 구조체
struct ProcessStats {
    DWORD pid;                 // 프로세스 ID
    std::wstring exeName;      // 실행 파일 이름 (예: chrome.exe)
    std::wstring windowTitle;  // 윈도우 창 제목 (상세 보기용)
    size_t memory;             // 메모리 사용량 (MB)
    double cpu;                // CPU 점유율 (%)
    int count;                 // 동일 이름 프로세스 개수 (요약 보기용)
};

// 개별 스레드의 정보
struct ThreadDetail {
    DWORD tid;                // Thread ID
    double cpuUsage;          // 이 스레드의 CPU 점유율 (%)
    DWORD64 rip;              // 명령어 주소 (Instruction Pointer)
    std::wstring moduleName;   // 소속 모듈 (예: UnityPlayer.dll)
    DWORD64 relativeOffset;   // 모듈 시작점으로부터의 거리 (Offset)
    DWORD priority;           // 스레드 우선순위
    std::wstring startModule; // 태생 모듈
    DWORD64 startOffset;      // 태생 지점의 오프셋
};

// 특정 PID 정밀 분석용 (무거운 정보)
struct ProcessDeepDetail {
    DWORD pid;
    std::wstring exePath;
    
    // CPU & Threads (내 점유율 / 시스템 전체 일꾼 수)
    double totalCpu;
    double kernelCpu;
    double userCpu;
    DWORD coreCount;
    DWORD threadCount;         // 현재 프로세스 스레드
    DWORD systemTotalThreads;  // 시스템 전체 스레드 합계
    DWORD priority;

    // 메모리 상세
    size_t workingSet;         // 물리 메모리
    size_t privateBytes;       // 전용 메모리 (누수 체크)
    size_t peakWorkingSet;     // 최대 기록
    DWORD pageFaults;          // 페이지 폴트
    size_t virtualSize;        // 가상 메모리

    // 자원 관리 (내 핸들 / 시스템 전체 핸들 수)
    DWORD handleCount;         // 현재 프로세스 핸들
    DWORD systemTotalHandles;  // 시스템 전체 핸들 합계

    std::vector<ThreadDetail> threads;
};