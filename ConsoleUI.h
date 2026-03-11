#pragma once
#include "Common.h"
#include <iostream>
#include <map>

class ConsoleUI {
public:
    static void DrawHeader(bool isDetail, const std::wstring& target = L"");
    static void DrawTable(const std::vector<ProcessStats>& list, bool isDetail, std::vector<std::wstring>& outNames);
    static std::wstring PromptSearch();
    static void DrawLoadingMessage(bool isInitial = false);
    static void DrawAnalysisScreen(const ProcessDeepDetail& data, char mode);
    static void DrawThreadDetail(const ProcessDeepDetail& data);
    static DWORD PromptThreadAnalysis();
    static void DrawAnalysisReport(DWORD tid, const std::map<std::string, int>& stats, int totalSamples);
};