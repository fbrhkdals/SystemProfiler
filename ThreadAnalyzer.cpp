#include "ThreadAnalyzer.h"
#include <dbghelp.h>
#include <vector>
#include <algorithm>
#include <sstream>
#include <iostream>

#pragma comment(lib, "dbghelp.lib")

void ThreadAnalyzer::AnalyzeThreadSampling(DWORD pid, DWORD tid, std::map<std::string, int>& outStats, int& totalSamples) {
    outStats.clear();
    totalSamples = 0;
    const int MAX_SAMPLES = 200;

    // 1. 프로세스 및 스레드 핸들 확보 (관리자 권한 필수)
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);

    if (!hProcess || !hThread) {
        if (hProcess) CloseHandle(hProcess);
        return;
    }

    // 2. 심볼 엔진 설정 (가장 확실한 설정)
    // SYMOPT_UNDNAME: C++ 이름을 예쁘게 복구
    // SYMOPT_LOAD_LINES: 소스 코드 줄 정보 로드
    // SYMOPT_AUTO_PUBLICS: 공개된 심볼 자동 로드
    SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_LOAD_LINES | SYMOPT_AUTO_PUBLICS);

    // 3. 심볼 검색 경로 구성
    // 현재폴더(.) ; 로컬캐시(C:\Symbols) ; 유니티서버 ; MS서버
    std::string searchPath = ".;SRV*C:\\Symbols*https://symbolserver.unity3d.com;SRV*C:\\Symbols*https://msdl.microsoft.com/download/symbols";
    
    // 4. 심볼 엔진 초기화
    if (!SymInitialize(hProcess, searchPath.c_str(), TRUE)) {
        // 초기화 실패 시 처리
    }

    // 5. 샘플링 루프 시작
    for (int i = 0; i < MAX_SAMPLES; i++) {
        CONTEXT ctx;
        ctx.ContextFlags = CONTEXT_ALL;
        
        if (SuspendThread(hThread) == (DWORD)-1) continue;

        if (GetThreadContext(hThread, &ctx)) {
            STACKFRAME64 frame = { 0 };
            frame.AddrPC.Offset = ctx.Rip;
            frame.AddrPC.Mode = AddrModeFlat;
            frame.AddrFrame.Offset = ctx.Rbp;
            frame.AddrFrame.Mode = AddrModeFlat;
            frame.AddrStack.Offset = ctx.Rsp;
            frame.AddrStack.Mode = AddrModeFlat;

            std::string finalIdentity = "";
            DWORD64 lastValidAddr = ctx.Rip;

            // [Deep Stack Walk] 실제 로직을 찾기 위해 호출 스택을 끝까지 파고듬
            for (int j = 0; j < 64; j++) {
                if (!StackWalk64(IMAGE_FILE_MACHINE_AMD64, hProcess, hThread, &frame, &ctx, NULL, 
                                 SymFunctionTableAccess64, SymGetModuleBase64, NULL))
                    break;

                if (frame.AddrPC.Offset == 0) break;

                char buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR)];
                PSYMBOL_INFO pSymbol = (PSYMBOL_INFO)buffer;
                pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
                pSymbol->MaxNameLen = MAX_SYM_NAME;

                DWORD64 displacement = 0;
                if (SymFromAddr(hProcess, frame.AddrPC.Offset, &displacement, pSymbol)) {
                    std::string symName = pSymbol->Name;
                    
                    // 시스템 대기/커널 함수(ntdll 등)는 건너뛰고 실제 로직(Unity/Game)만 타겟팅
                    if (symName.find("Nt") != 0 && symName.find("Rtl") != 0 && 
                        symName.find("Ki") != 0 && symName.find("Wait") == std::string::npos) 
                    {
                        IMAGEHLP_MODULE64 modInfo = { sizeof(modInfo) };
                        std::string modName = "Unknown";
                        if (SymGetModuleInfo64(hProcess, frame.AddrPC.Offset, &modInfo)) {
                            modName = modInfo.ModuleName;
                        }

                        // 소스 코드 라인 정보까지 있다면 추가 (PDB가 있을 때만 작동)
                        IMAGEHLP_LINE64 line = { sizeof(line) };
                        DWORD dispLine = 0;
                        if (SymGetLineFromAddr64(hProcess, frame.AddrPC.Offset, &dispLine, &line)) {
                            std::string fileName = line.FileName;
                            fileName = fileName.substr(fileName.find_last_of("\\") + 1);
                            finalIdentity = symName + " (" + fileName + ":" + std::to_string(line.LineNumber) + ")|" + modName;
                        } else {
                            finalIdentity = symName + "|" + modName;
                        }
                        break; 
                    }
                } else {
                    lastValidAddr = frame.AddrPC.Offset;
                }
            }

            // 끝까지 이름을 못 찾은 경우 (JIT 또는 PDB 누락)
            if (finalIdentity.empty()) {
                IMAGEHLP_MODULE64 modInfo = { sizeof(modInfo) };
                std::string modName = (SymGetModuleInfo64(hProcess, lastValidAddr, &modInfo)) ? modInfo.ModuleName : "Dynamic/JIT";
                std::stringstream ss;
                ss << "0x" << std::hex << std::uppercase << lastValidAddr << "|" << modName;
                finalIdentity = ss.str();
            }

            outStats[finalIdentity]++;
            totalSamples++;
        }
        ResumeThread(hThread);
        Sleep(1); // 샘플링 간격
    }

    // 6. 자원 해제
    SymCleanup(hProcess);
    CloseHandle(hThread);
    CloseHandle(hProcess);
}