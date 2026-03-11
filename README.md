# 🚀 Windows Deep Process Analyzer

Windows 시스템의 프로세스를 실시간으로 모니터링하고, **PDB 심볼 분석 및 Stack Walking**을 통해 특정 스레드의 실행 경로와 성능 병목 지점을 정밀 분석하는 C++ 기반 도구입니다.

---

## ✨ 주요 기능 (Key Features)

### 1. 실시간 프로세스 자원 모니터링
* **Smart Grouping:** 동일한 `.exe` 프로세스들을 그룹화하여 통합 자원(CPU, RAM) 점유율을 계산합니다.
* **Multi-Layer Identification:** 창 제목 > 서비스 이름 > 파일 버전 설명 > 실행 파일명 순의 우선순위를 적용하여 프로세스의 정체를 명확히 식별합니다.
* **Real-time Sorting:** CPU 및 메모리 사용량에 따른 동적 리스트 정렬을 지원합니다.

### 2. 정밀 스레드 샘플링 분석 (Profiling)
* **Stack Walking:** `StackWalk64`를 통해 스레드의 호출 스택을 역추적하여 함수 호출 경로를 파악합니다.
* **Symbol Restoration:** (PDB 존재 시) 메모리 주소를 실제 함수 이름과 소스 파일 경로, 라인 번호로 복구합니다.
* **Hot Spot 탐지:** 지정된 횟수만큼 스레드 문맥을 샘플링하여 가장 많이 점유된 함수의 통계를 제공합니다.

---

## 🛠 기술 스택 (Technical Stack)

* **Language:** C++17
* **Libraries:** `Win32 API`, `DbgHelp.lib`, `Psapi.lib`, `Version.lib`
* **APIs:** Toolhelp32 Snapshot, GetThreadContext, SymFromAddr 등

---

## ⚙️ 실행 및 조작 방법

> **⚠️ 필수:** 모든 프로세스 핸들 및 스레드 컨텍스트에 접근하기 위해 반드시 **관리자 권한**으로 실행하십시오.

| 키 | 기능 |
| :--- | :--- |
| **F** | 검색 / 상세 리스트 진입 / PID 입력(정밀 분석 시작) |
| **D** | 상세 분석 화면 내에서 '스레드 상세 모드' 전환 |
| **B** | 뒤로 가기 (이전 화면 복귀) |
| **C / M** | CPU 사용량 기준 / 메모리 사용량 기준 리스트 정렬 |
| **R** | 시스템 스냅샷 강제 새로고침 |

---

## 📂 프로젝트 구조
* `ProcessProvider`: 시스템 로우 레벨 데이터 수집 엔진.
* `ProcessManager`: 데이터 가공, 그룹화 및 정렬 로직.
* `ThreadAnalyzer`: 스레드 샘플링 및 심볼 복구 엔진.
* `ConsoleUI`: 가독성 높은 CLI 인터페이스 및 사용자 입력 처리.

---
