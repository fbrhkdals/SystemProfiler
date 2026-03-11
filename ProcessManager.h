#pragma once
#include "Common.h"
#include <map>

class ProcessManager {
public:
    void SetRawData(const std::vector<ProcessStats>& data) { rawData = data; }
    
    // 요약 보기용: 이름을 기준으로 그룹화
    std::vector<ProcessStats> GetGroupedSummary(SortBy sort);
    // 상세 보기용: 특정 이름의 프로세스들만 필터링
    std::vector<ProcessStats> GetDetailList(const std::wstring& exeName, SortBy sort);

private:
    std::vector<ProcessStats> rawData;
};