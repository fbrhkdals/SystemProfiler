#pragma once
#include "common.h"
#include <iostream>
#include <iomanip>

class ProcessAnalyzer {
public:
    // 새로운 프로세스 분석 시 이전 CPU 기록을 0으로 초기화
    static void ResetHistory();

    // 실시간으로 모든 정보를 긁어오는 핵심 함수
    static void GetUpdate(DWORD pid, ProcessDeepDetail* d);

    // 바이트를 B, KB, MB, GB로 자동 변환
    static std::wstring FormatBytes(size_t bytes);

    // 우선순위 정수값을 읽기 쉬운 문자열로 변환
    static std::wstring GetPriorityStr(DWORD priority);

private:
    // 스레드 내부 주소를 캡처하는 핵심 로직
    static void CaptureThreadContext(HANDLE hProcess, DWORD tid, ThreadDetail& outThread);
};