#pragma once
#include "Common.h"

// 콜백 함수를 위한 구조체 선언
struct SearchData { DWORD pid; std::wstring title; };

class ProcessProvider {
public:
    // 시스템의 모든 프로세스 정보를 스캔
    static std::vector<ProcessStats> GetAllProcesses();
    
    // 특정 PID의 창 제목을 가져옴 (상세보기 실시간 갱신용)
    static std::wstring GetWindowTitle(DWORD pid);

private:
    // 파일 상세 설명(Description) 추출
    static std::wstring GetFileDescription(const std::wstring& filePath);

    // 메모리 및 CPU 시간 수집
    static size_t GetMemoryUsage(HANDLE hProcess);
    static double GetProcessRawTime(HANDLE hProcess);
};