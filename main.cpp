#include "ProcessProvider.h"
#include "ProcessAnalyzer.h"
#include "ProcessManager.h"
#include "ThreadAnalyzer.h"
#include "ConsoleUI.h"
#include <conio.h>
#include <windows.h>
#include <memory>

// 콘솔 스크롤 및 버퍼 설정
void SetupConsole() {
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    COORD size = { 120, 1000 }; // 가로 120자, 세로 1000줄까지 저장
    SetConsoleScreenBufferSize(hOut, size);
}

// 시스템의 모든 프로세스를 들여다볼 수 있는 '디버그 권한' 활성화
bool EnableDebugPrivilege() {
    HANDLE hToken;
    LUID luid;
    TOKEN_PRIVILEGES tp;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return false;

    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
        CloseHandle(hToken);
        return false;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        CloseHandle(hToken);
        return false;
    }

    CloseHandle(hToken);
    return true;
}

// 실시간 정밀 분석 루프 제어
void RunRealTimeAnalysis(DWORD pid) {
    // 모드 종류: 'M'(메모리), 'C'(CPU), 'D'(스레드 정밀 분석)
    char currentMode = 'M'; 
    HANDLE hInput = GetStdHandle(STD_INPUT_HANDLE);

    // [1. 메모리 할당] 분석 시작 시점에 구조체를 생성합니다. (RAM 점유 시작)
    // std::unique_ptr를 사용하여 관리가 끝나면 자동으로 메모리가 파기되도록 합니다.
    std::unique_ptr<ProcessDeepDetail> data = std::make_unique<ProcessDeepDetail>();
    
    // [2. 릴레이 초기화] 이전 프로세스의 기록이 섞이지 않도록 초기화
    ProcessAnalyzer::ResetHistory();

    while (true) {
        // [3. 데이터 수집] 릴레이 방식으로 1초마다 업데이트
        // (주의: ProcessAnalyzer::GetUpdate가 포인터를 받도록 수정되어야 함)
        ProcessAnalyzer::GetUpdate(pid, data.get());
        
        // --- UI 출력 분기 ---
        if (currentMode == 'D') {
            // 스레드 정밀 분석 화면 (TID, RIP, Module, Offset)
            ConsoleUI::DrawThreadDetail(*data);
        } else {
            // 프로세스 상세 화면 (기존 메모리/CPU 분석)
            ConsoleUI::DrawAnalysisScreen(*data, currentMode);
            std::wcout << L" [D] 스레드 상세분석 진입" << std::endl;
        }

        // 최대 1초 대기 (키 입력 시 조기 탈출)
        DWORD waitResult = WaitForSingleObject(hInput, 1000);

        if (waitResult == WAIT_OBJECT_0) {
            INPUT_RECORD ir;
            DWORD read;
            while (PeekConsoleInputW(hInput, &ir, 1, &read) && read > 0) {
                ReadConsoleInputW(hInput, &ir, 1, &read);
                if (ir.EventType == KEY_EVENT && ir.Event.KeyEvent.bKeyDown) {
                    wchar_t key = ir.Event.KeyEvent.wVirtualKeyCode;
                    
                    if (key == 'M') currentMode = 'M';
                    else if (key == 'C') currentMode = 'C';
                    else if (key == 'D') currentMode = 'D'; // 스레드 모드
                    else if (key == 'F' && currentMode == 'D') {
                        DWORD targetTID = ConsoleUI::PromptThreadAnalysis(); 
                        
                        if (targetTID != 0) {
                            // 1. 데이터 수집 (화면은 잠시 멈춤)
                            std::map<std::string, int> stats;
                            int totalSamples = 100; // 샘플링 횟수
                            
                            // 실제 분석 로직 수행
                            ThreadAnalyzer::AnalyzeThreadSampling(pid, targetTID, stats, totalSamples);

                            // 2. 새 페이지로 전환하여 결과 출력
                            ConsoleUI::DrawAnalysisReport(targetTID, stats, totalSamples);

                            // 3. B 키 전용 대기 루프 (여기서 B를 눌러야 목록으로 나감)
                            while (true) {
                                if (_kbhit()) {
                                    wchar_t subKey = _getwch();
                                    if (subKey == L'b' || subKey == L'B') {
                                        break; // 루프 탈출 -> DrawThreadDetail로 자동 복귀
                                    }
                                }
                                Sleep(10);
                            }
                        }
                    }
                    else if (key == 'B') {
                        // [4. 메모리 즉시 파기 및 단계적 뒤로가기]
                        // 스레드 상세 모드('D')라면 다시 일반 분석 화면으로, 
                        // 일반 분석 화면이라면 메인으로 나갑니다.
                        if (currentMode == 'D') {
                            currentMode = 'C'; 
                        } else {
                            ProcessAnalyzer::ResetHistory(); 
                            return; 
                        }
                    }
                    break; 
                }
            }
        }
    }
}

int main() {
    SetupConsole(); // 콘솔 환경 설정
    EnableDebugPrivilege(); // 관리자 권한 획득 시도

    std::wcout.imbue(std::locale("korean"));
    
    ProcessManager manager;
    SortBy currentSort = SortBy::MEMORY;
    std::wstring focusTarget = L""; 
    std::vector<std::wstring> currentGroupNames; 

    ConsoleUI::DrawLoadingMessage(true);
    manager.SetRawData(ProcessProvider::GetAllProcesses());

    bool shouldRedraw = true; 

    while (true) {
        if (shouldRedraw) {
            bool isDetail = !focusTarget.empty();
            currentGroupNames.clear();

            // 데이터 수집
            auto displayList = isDetail ? 
                manager.GetDetailList(focusTarget, currentSort) : 
                manager.GetGroupedSummary(currentSort);

            // [추가 로직] 실제 프로세스 총 개수 계산 (작업 관리자 일치용)
            size_t totalActualCount = 0;
            if (!isDetail) {
                for (const auto& item : displayList) {
                    totalActualCount += item.count; // 그룹화된 개수(n)를 모두 합산
                }
            } else {
                totalActualCount = displayList.size();
            }

            // UI 출력
            ConsoleUI::DrawHeader(isDetail, focusTarget);
            
            // 상단 정보 바 수정
            std::wcout << L" [ 정보 ] 종류: " << displayList.size() << L" 종 | ";
            std::wcout << L"실제 프로세스 총합: " << totalActualCount << L" 개" << std::endl;
            std::wcout << L"----------------------------------------------------------------------" << std::endl;

            ConsoleUI::DrawTable(displayList, isDetail, currentGroupNames);
            
            shouldRedraw = false; 
        }

        // --- [입력 처리] ---
        if (GetAsyncKeyState('R') & 0x8000) {
            while (GetAsyncKeyState('R') & 0x8000) Sleep(10);
            ConsoleUI::DrawLoadingMessage(false);
            manager.SetRawData(ProcessProvider::GetAllProcesses()); 
            shouldRedraw = true;
        }
        
        if (GetAsyncKeyState('M') & 0x8000) { 
            while (GetAsyncKeyState('M') & 0x8000) Sleep(10);
            currentSort = SortBy::MEMORY; 
            shouldRedraw = true; 
        }
        if (GetAsyncKeyState('C') & 0x8000) { 
            while (GetAsyncKeyState('C') & 0x8000) Sleep(10);
            currentSort = SortBy::CPU; 
            shouldRedraw = true; 
        }
        
        if (!focusTarget.empty() && (GetAsyncKeyState('B') & 0x8000)) { 
            while (GetAsyncKeyState('B') & 0x8000) Sleep(10);
            focusTarget = L""; 
            shouldRedraw = true; 
        }

        // F 키 처리 (메인에서는 그룹 선택, 상세 리스트에서는 PID 선택)
        if (GetAsyncKeyState('F') & 0x8000) {
            while (GetAsyncKeyState('F') & 0x8000) Sleep(10);
            while (_kbhit()) _getch(); 

            if (focusTarget.empty()) {
                // [1단계] 메인 화면: 그룹 이름이나 번호로 상세 리스트 진입
                std::wstring input = ConsoleUI::PromptSearch();
                if (!input.empty()) {
                    bool found = false;
                    std::wstring targetName = L"";

                    try {
                        int idx = std::stoi(input);
                        if (idx > 0 && idx <= (int)currentGroupNames.size()) {
                            targetName = currentGroupNames[idx - 1];
                            found = true;
                        }
                    } catch (...) {
                        for (const auto& name : currentGroupNames) {
                            if (name == input) { targetName = name; found = true; break; }
                        }
                    }

                    if (found) { focusTarget = targetName; shouldRedraw = true; }
                    else {
                        std::wcout << L"\n [오류] 찾을 수 없습니다: " << input << std::endl;
                        Sleep(1000); shouldRedraw = true;
                    }
                }
            } else {
                // [2단계] 상세 리스트: PID를 직접 입력받아 실시간 정밀 분석 진입
                std::wcout << L"\n [분석] 정밀 관찰할 PID 입력 (ESC 취소): ";
                std::wstring pidInput = L"";
                
                // 간단한 PID 입력 처리
                while (true) {
                    if (_kbhit()) {
                        wchar_t ch = _getwch();
                        if (ch == 27) { pidInput = L""; break; } // ESC
                        if (ch == 13) break; // Enter
                        if (ch == 8) { if (!pidInput.empty()) { pidInput.pop_back(); std::wcout << L"\b \b"; } }
                        else if (iswdigit(ch)) { pidInput += ch; std::wcout << ch; }
                    }
                }

                if (!pidInput.empty()) {
                    DWORD targetPid = std::stoul(pidInput);
                    // 실시간 분석 루프 실행 (B를 누를 때까지 여기서 안 나감)
                    RunRealTimeAnalysis(targetPid);
                    
                    // 루프 종료 후 돌아오면 화면 다시 그리기
                    shouldRedraw = true;
                } else {
                    shouldRedraw = true;
                }
            }
        }
        Sleep(30); 
    }

    return 0;
}