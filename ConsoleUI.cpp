#include "ConsoleUI.h"
#include "ProcessAnalyzer.h"
#include <iomanip>
#include <conio.h>
#include <sstream>
#include <algorithm>
#include <map>

void ConsoleUI::DrawHeader(bool isDetail, const std::wstring& target) {
    system("cls");
    std::wcout << L"=== SystemProfiler ===" << std::endl;
    if (!isDetail) {
        std::wcout << L"[R]새로고침 | [M]메모리순 | [C]CPU순 | [F]상세보기" << std::endl;
        std::wcout << L"\n--- 전체 프로세스 요약 ---" << std::endl;
    } else {
        std::wcout << L"[M]메모리순 | [C]CPU순 | [F]상세보기 | [B]뒤로가기" << std::endl;
        std::wcout << L"\n--- 상세 내역: " << target << L" ---" << std::endl;
    }
}

int GetVisualWidth(const std::wstring& s) {
    int width = 0;
    for (wchar_t ch : s) {
        // 한글 범위(AC00~D7A3) 및 한글 자모 등은 2칸으로 계산
        if (ch >= 0x0800) width += 2; 
        else width += 1;
    }
    return width;
}

std::wstring FitToWidth(std::wstring s, int maxWidth) {
    // 1. 먼저 너무 길면 자르기 (한글 고려)
    while (GetVisualWidth(s) > maxWidth - 3) {
        s.pop_back();
    }
    if (GetVisualWidth(s) < maxWidth - 3 && s.length() < s.length() + 3) {
        // 자른 흔적 표시 (옵션)
    }

    // 2. 남은 공간만큼 공백 채우기
    int currentWidth = GetVisualWidth(s);
    return s + std::wstring(max(0, maxWidth - currentWidth), L' ');
}

void ConsoleUI::DrawTable(const std::vector<ProcessStats>& list, bool isDetail, std::vector<std::wstring>& outNames) {
    outNames.clear(); 

    if (!isDetail) {
        // 헤더 출력 (너비: ID 6, Name 35, Mem 15, CPU 10)
        std::wcout << L"ID    " << L"PROCESS NAME                       " << L"       MEM(MB)" << L"    CPU(%)" << std::endl;
        std::wcout << L"----------------------------------------------------------------------" << std::endl;

        int idx = 1;
        for (const auto& g : list) {
            outNames.push_back(g.exeName);

            // 이름 + 개수 조합
            std::wstring nameWithCount = g.exeName + L" (" + std::to_wstring(g.count) + L")";
            
            // [핵심] 한글 폭에 맞춰 강제 정렬 (35칸 고정)
            std::wstring formattedName = FitToWidth(nameWithCount, 35);

            std::wcout << std::left << std::setw(6) << idx++ 
                       << formattedName 
                       << std::right << std::setw(15) << g.memory 
                       << std::setw(10) << std::fixed << std::setprecision(1) << g.cpu << std::endl;

        }
    } else {
        // 상세 헤더 (PID 10, Title 45, Mem 12, CPU 10)
        std::wcout << L"PID       " << L"WINDOW TITLE                                 " << L"     MEM(MB)" << L"   CPU(%)" << std::endl;
        std::wcout << L"----------------------------------------------------------------------" << std::endl;

        for (const auto& g : list) {
            std::wstring t = g.windowTitle.empty() ? L"(No Window)" : g.windowTitle;
            
            // [핵심] 윈도우 타이틀은 한글이 많으므로 45칸 고정 정렬
            std::wstring formattedTitle = FitToWidth(t, 45);

            std::wcout << std::left << std::setw(10) << g.pid 
                       << formattedTitle 
                       << std::right << std::setw(12) << g.memory 
                       << std::setw(10) << std::fixed << std::setprecision(1) << g.cpu << std::endl;
        }
    }
}

std::wstring ConsoleUI::PromptSearch() {
    std::wcout << L"\n[Focus] 번호/이름 입력 (ESC 취소): ";
    std::wstring input = L"";
    while (true) {
        if (_kbhit()) {
            wchar_t ch = _getwch();
            if (ch == 27) return L"";
            if (ch == 13) break;
            if (ch == 8) { if (!input.empty()) { input.pop_back(); std::wcout << L"\b \b"; } }
            else { input += ch; std::wcout << ch; }
        }
        Sleep(10);
    }
    return input;
}

void ConsoleUI::DrawLoadingMessage(bool isInitial) {
    system("cls");
    if (isInitial) {
        std::wcout << L"데이터를 불러오는 중입니다... " << std::endl;
    } else {
        std::wcout << L"시스템 정보를 새로고침 중입니다... " << std::endl;
    }
}

void ConsoleUI::DrawAnalysisScreen(const ProcessDeepDetail& data, char mode) {
    system("cls");
    
    // 1. 실행 파일명 추출 (경로에서 마지막 \ 뒤의 문자열)
    std::wstring fileName = L"Unknown";
    if (!data.exePath.empty()) {
        size_t lastSlash = data.exePath.find_last_of(L"\\");
        fileName = (lastSlash != std::wstring::npos) ? data.exePath.substr(lastSlash + 1) : data.exePath;
    }

    // 2. 상단 헤더 및 코어 정보 출력
    std::wcout << L"================================================" << std::endl;
    std::wcout << L" [ 정밀 실시간 분석 - " << fileName << L" ]" << std::endl;
    std::wcout << L" [M]메모리 모드   [C]CPU 모드   [B]뒤로가기" << std::endl;
    std::wcout << L"================================================" << std::endl;
    
    // [핵심] PID와 함께 이 시스템의 코어 수와 최대 이론적 점유율 표시
    std::wcout << L" PID: " << data.pid 
               << L" | 논리 코어: " << data.coreCount 
               << L" (Max: " << data.coreCount * 100 << L"%)" << std::endl;
    std::wcout << L"------------------------------------------------" << std::endl;

    // 3. 데이터 유효성 검사 및 모드별 출력
    if (data.privateBytes == 0 && data.totalCpu == 0) {
        std::wcout << L"\n [!] 데이터를 가져올 수 없습니다. (권한 부족 혹은 프로세스 종료)" << std::endl;
    }
    else if (mode == 'M' || mode == 'm') {
        // --- 메모리 분석 모드 ---
        std::wcout << L">> [ MEMORY ANALYSIS ]" << std::endl;
        std::wcout << L" - 전용 메모리 (Private): " << ProcessAnalyzer::FormatBytes(data.privateBytes) << std::endl;
        std::wcout << L" - 물리 메모리 (Working): " << ProcessAnalyzer::FormatBytes(data.workingSet) << std::endl;
        std::wcout << L" - 최대 점유 기록 (Peak) : " << ProcessAnalyzer::FormatBytes(data.peakWorkingSet) << std::endl;
        std::wcout << L" - 가상 메모리 (Virtual) : " << ProcessAnalyzer::FormatBytes(data.virtualSize) << std::endl;
        std::wcout << L" - 페이지 폴트 (Faults)  : " << data.pageFaults << L" 건" << std::endl;
    } 
    else {
        // --- CPU 및 리소스 분석 모드 (절대 성능 기준) ---
        std::wcout << L">> [ CPU & RESOURCE ANALYSIS ]" << std::endl;
        
        // 절대 성능 점유율 출력 (100%를 넘을 수 있음)
        std::wcout << L" - 전체 CPU 점유율: " << std::fixed << std::setprecision(2) << data.totalCpu << L" %";
        
        // 시각적 가이드: 코어 1개 분량을 넘게 쓰고 있다면 표시
        if (data.totalCpu >= 100.0) {
            std::wcout << L" [Multicore Active]";
        }
        std::wcout << std::endl;

        std::wcout << L" - 커널 점유율     : " << std::fixed << std::setprecision(2) << data.kernelCpu << L" %" << std::endl;
        std::wcout << L" - 유저 점유율     : " << std::fixed << std::setprecision(2) << data.userCpu << L" %" << std::endl;

        // 스레드 및 핸들 시스템 점유 비중 계산
        double tRatio = (data.systemTotalThreads > 0) ? (data.threadCount * 100.0 / data.systemTotalThreads) : 0;
        std::wcout << L" - 스레드 개수     : " << data.threadCount << L" / " << data.systemTotalThreads 
                   << L" (" << std::fixed << std::setprecision(1) << tRatio << L"%)" << std::endl;

        double hRatio = (data.systemTotalHandles > 0) ? (data.handleCount * 100.0 / data.systemTotalHandles) : 0;
        std::wcout << L" - 핸들 개수       : " << data.handleCount << L" / " << data.systemTotalHandles 
                   << L" (" << std::fixed << std::setprecision(1) << hRatio << L"%)" << std::endl;

        std::wcout << L" - 우선순위 클래스 : " << ProcessAnalyzer::GetPriorityStr(data.priority) << std::endl;
    }

    // 4. 하단 경로 정보
    std::wcout << L"------------------------------------------------" << std::endl;
    std::wcout << L" 전체 경로: " << (data.exePath.empty() ? L"Access Denied" : data.exePath) << std::endl;
    std::wcout << L"================================================" << std::endl;
}

void ConsoleUI::DrawThreadDetail(const ProcessDeepDetail& data) {
    system("cls");
    // 1. 깜빡임 방지: 화면 전체를 지우지 않고 커서를 (0,0)으로 이동
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    COORD coord = { 0, 0 };
    SetConsoleCursorPosition(hOut, coord);

    // 2. 헤더 출력
    std::wcout << L"================================================================================" << std::endl;
    std::wcout << L" [ 스레드 정밀 분석 (Thread Trace) - PID: " << std::setw(6) << data.pid << L" ]" << std::endl;
    std::wcout << L" [B]뒤로가기 | [F] TID 정밀 분석 (입력 시 화면 일시정지) | CPU 기준 25개" << std::endl;
    std::wcout << L"================================================================================" << std::endl;

    // 3. 테이블 헤더 (태생 정보를 포함하여 너비 재조정)
    // 너비 분배: TID(7), CPU(7), Start Module(20), Current Module(20), Offset(12), RIP(14)
    std::wcout << std::left << std::setw(7)  << L"TID" 
               << std::setw(7)  << L"CPU(%)" 
               << std::setw(20) << L"START(태생)"   // <--- 중요: 어디서 만든 스레드인가?
               << std::setw(20) << L"CURRENT(현재)" // <--- 현재 ntdll에 있어도 Start를 보면 됨
               << std::setw(12) << L"OFFSET" 
               << std::setw(14) << L"RIP" << std::endl;
    std::wcout << L"--------------------------------------------------------------------------------" << std::endl;

    // 4. 스레드 리스트 출력
    if (data.threads.empty()) {
        std::wcout << L"\n [!] 수집된 스레드 정보가 없습니다. (권한 부족)" << std::endl;
        // 남은 화면을 공백으로 채워 이전 잔상을 지움 (덮어쓰기 방식의 특징)
        for(int i=0; i<10; ++i) std::wcout << L"                                                                                " << std::endl;
    } else {
        int displayCount = 0;
        for (const auto& th : data.threads) {
            if (displayCount > 25) break; // 너무 많으면 화면을 넘어가므로 제한

            // 텍스트 포맷팅
            std::wstring startMod = FitToWidth(th.startModule.empty() ? L"[Unknown]" : th.startModule, 20);
            std::wstring currentMod = FitToWidth(th.moduleName.empty() ? L"[Unknown]" : th.moduleName, 20);

            // 주소 포맷팅
            std::wstringstream ssOffset;
            ssOffset << L"+" << std::hex << std::uppercase << th.relativeOffset;
            
            std::wstringstream ssRip;
            ssRip << L"0x" << std::hex << std::uppercase << th.rip;

            // 출력
            std::wcout << std::left << std::setw(7) << th.tid 
                       << std::setw(7) << std::fixed << std::setprecision(1) << th.cpuUsage
                       << startMod
                       << currentMod
                       << std::setw(12) << ssOffset.str()
                       << std::setw(14) << ssRip.str() << std::endl;
            
            displayCount++;
        }
        
        // 이전 데이터 잔상 제거용 빈 줄 (스레드 개수가 줄어들었을 때 대비)
        for(int i=0; i < (25 - displayCount); ++i) 
            std::wcout << L"                                                                                " << std::endl;
    }

    std::wcout << L"================================================================================" << std::endl;
}

DWORD ConsoleUI::PromptThreadAnalysis() {
    // 1. 현재 입력창 텍스트 출력
    std::wstring prompt = L"\n [분석 대상 TID 입력] (숫자만 입력, ESC 취소): ";
    std::wcout << prompt;
    
    std::wstring input = L"";
    while (true) {
        if (_kbhit()) {
            wchar_t ch = _getwch();
            
            // --- ESC 취소 시 처리 ---
            if (ch == 27) { 
                // 방금 출력한 프롬프트 + 입력된 글자 수만큼 뒤로 가서 지우기
                int totalLen = GetVisualWidth(prompt) + GetVisualWidth(input);
                
                // 줄의 맨 앞으로 커서를 옮기거나 백스페이스로 지움
                std::wcout << L"\r"; // 커서를 줄 맨 앞으로
                for(int i=0; i < totalLen + 5; i++) std::wcout << L" "; // 공백으로 덮어쓰기
                std::wcout << L"\r"; // 다시 맨 앞으로 (다음 출력이 깨끗하게 나오도록)
                
                return 0; 
            }

            if (ch == 13) break; // Enter
            
            if (ch == 8) { // Backspace
                if (!input.empty()) {
                    input.pop_back();
                    std::wcout << L"\b \b";
                }
            }
            else if (iswdigit(ch)) {
                input += ch;
                std::wcout << ch;
            }
        }
        Sleep(10);
    }

    return input.empty() ? 0 : std::stoul(input);
}

void ConsoleUI::DrawAnalysisReport(DWORD tid, const std::map<std::string, int>& stats, int totalSamples) {
    system("cls");
    
    std::wcout << L"============================================================================================" << std::endl;
    std::wcout << L" [ Thread ID: " << std::left << std::setw(5) << tid << L" 시스템 프로세스 정밀 성능 분석 리포트 ]" << std::endl;
    std::wcout << L"============================================================================================" << std::endl;
    
    // 헤더 정렬 (FitToWidth 활용 가능)
    std::wcout << L" " << std::left << std::setw(45) << L"실행 중인 함수 (또는 메모리 주소)" 
               << L" | " << std::setw(20) << L"소속 모듈(DLL/EXE)" 
               << L" | " << L"CPU 점유율" << std::endl;
    std::wcout << L"--------------------------------------------------------------------------------------------" << std::endl;

    std::vector<std::pair<std::string, int>> sortedStats(stats.begin(), stats.end());
    std::sort(sortedStats.begin(), sortedStats.end(), [](auto& a, auto& b) { return a.second > b.second; });

    for (const auto& item : sortedStats) {
        float percent = (float)item.second / totalSamples * 100.0f;
        if (percent < 0.1f) continue;

        std::string fullData = item.first;
        std::string funcName = "Unknown", moduleName = "Unknown";

        size_t delimeterPos = fullData.find('|');
        if (delimeterPos != std::string::npos) {
            funcName = fullData.substr(0, delimeterPos);
            moduleName = fullData.substr(delimeterPos + 1);
        }

        std::wstring wFuncName(funcName.begin(), funcName.end());
        std::wstring wModuleName(moduleName.begin(), moduleName.end());

        const wchar_t* impact = (percent >= 10.0f) ? L">>" : L"  ";
        
        std::wstring formattedFunc = FitToWidth(wFuncName, 42);
        std::wstring formattedMod = FitToWidth(wModuleName, 20);

        std::wcout << impact << L" " << formattedFunc << L" | " << formattedMod 
                   << L" | " << std::fixed << std::setprecision(1) << percent << L"%" << std::endl;
    }

    std::wcout << L"--------------------------------------------------------------------------------------------" << std::endl;
    std::wcout << L" [도움말] 0x... 주소만 뜨는 경우, 해당 모듈의 디버그 심볼(PDB)이 없음을 의미합니다." << std::endl;
    std::wcout << L" [B] 뒤로가기" << std::endl;
}