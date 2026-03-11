#pragma once
#include <windows.h>
#include <string>
#include <map>
#include <vector>

/**
 * @brief 스레드 정밀 샘플링 분석 클래스
 */
class ThreadAnalyzer {
public:
    static void AnalyzeThreadSampling(
        DWORD pid, // 대상 프로세스 ID
        DWORD tid, // 대상 스레드 ID
        std::map<std::string, int>& outStats, // 함수명과 히트 수(count)를 담을 맵
        int& totalSamples // 성공한 총 샘플링 횟수
    );
};