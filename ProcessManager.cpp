#include "ProcessManager.h"
#include "ProcessProvider.h"
#include <algorithm>
#include <map>

// 외부에서 정의된 서비스 이름 찾기 함수를 쓰기 위해 선언 (또는 ProcessProvider에 포함)
extern std::wstring GetServiceNameFromPID(DWORD pid); 

std::vector<ProcessStats> ProcessManager::GetGroupedSummary(SortBy sort) {
    std::map<std::wstring, ProcessStats> groups;
    for (const auto& raw : rawData) {
        if (groups.find(raw.exeName) == groups.end()) {
            groups[raw.exeName] = { 0, raw.exeName, raw.exeName, 0, 0.0, 0 };
        }
        groups[raw.exeName].memory += raw.memory;
        groups[raw.exeName].cpu += raw.cpu;
        groups[raw.exeName].count++;

        // 그룹 대표 이름 결정
        if (raw.windowTitle != L"-" && (groups[raw.exeName].windowTitle == raw.exeName || groups[raw.exeName].windowTitle == L"-")) {
            groups[raw.exeName].windowTitle = raw.windowTitle;
        }
    }

    std::vector<ProcessStats> result;
    for (auto& p : groups) result.push_back(p.second);

    std::sort(result.begin(), result.end(), [sort](const ProcessStats& a, const ProcessStats& b) {
        return (sort == SortBy::CPU) ? a.cpu > b.cpu : a.memory > b.memory;
    });
    return result;
}

std::vector<ProcessStats> ProcessManager::GetDetailList(const std::wstring& exeName, SortBy sort) {
    std::vector<ProcessStats> details;
    for (const auto& raw : rawData) {
        if (raw.exeName == exeName) {
            ProcessStats p = raw;

            // [핵심] 상세 페이지에서 이름을 한 번 더 정밀하게 확인
            // 1. 우선 실시간 창 제목 확인
            std::wstring liveTitle = ProcessProvider::GetWindowTitle(p.pid);
            
            if (liveTitle != L"-") {
                p.windowTitle = liveTitle;
            } 
            // 2. 창 제목이 없다면 서비스 이름 확인 (svchost 등)
            else {
                std::wstring srvName = GetServiceNameFromPID(p.pid);
                if (!srvName.empty()) {
                    p.windowTitle = srvName;
                }
                // 3. 둘 다 없으면 이미 들어있는 description을 유지하거나 파일명 사용
            }
            
            details.push_back(p);
        }
    }

    std::sort(details.begin(), details.end(), [sort](const ProcessStats& a, const ProcessStats& b) {
        return (sort == SortBy::CPU) ? a.cpu > b.cpu : a.memory > b.memory;
    });
    return details;
}