# Pwanable_AI_Agent
### 프로젝트 개요

LLM 기반 **AI Agent가 보안 워게임 문제를 스스로 분석하고 해결하는 시스템**을 개발합니다.

Agent에게 Web, Pwnable 등 분야별 보안 도구와 실행 환경을 제공하고,  
**문제 분석 → 도구 실행 → 결과 분석 → 재시도** 과정을 반복하여 Flag를 획득하도록 합니다.

또한 풀이 과정과 실행 기록을 Memory로 관리하여 이후 문제 해결에 활용할 수 있는 구조를 구현합니다.

---

### 프로젝트장

**CAUtion 0기 이병현**

---

### 프로젝트 방식

#### 공통 Agent/Core 개발 + Pwnable 하네스 구성

- **공통**
  - LLM API
  - Tool Calling
  - Memory
  - Logging
  - 기타 Agent 핵심 기능 개발

- **Pwnable 분야**
  - Pwnable 문제 풀이에 필요한 도구 구성
  - Agent가 도구를 사용할 수 있는 실행 환경 구축
  - 분야에 적합한 Harness 설계 및 구현

- **평가 및 분석**
  - 완성된 Agent를 실제 워게임 문제에 적용
  - **문제 해결 성공률** 비교
  - **풀이 과정** 분석
  - **Tool 사용 방식 및 호출 횟수** 분석
  - Harness 구성에 따른 성능 차이 비교

---

### 프로젝트 목적

단순히 LLM에게 문제 풀이를 질문하는 것을 넘어,  
**AI가 직접 보안 도구를 활용하여 문제를 해결하는 Agent**를 구현하는 것이 목표입니다.

프로젝트를 통해 다음 내용을 함께 학습합니다.

- **AI Agent 구조 및 동작 원리**
- **LLM API 및 Tool Calling**
- **Memory / Logging / Planning 구조**
- **System / Pwnable 보안 지식**
- **보안 도구를 Agent와 연결하는 Harness 구성**

최종적으로 **Harness의 구성에 따라 Agent의 문제 해결 성능이 어떻게 달라지는지 분석**하고,  
효율적인 보안 워게임 풀이 Agent 구조를 탐구합니다.

---

### 분석 보고서 저장

단일 실행 결과와 도구 호출 과정은 `--output`으로 Markdown 또는 텍스트 파일에 저장할 수 있습니다.

```bash
python agent.py --file ./challenge --output analysis.md "Analyze this pwnable challenge"
```

`--output`은 `.md`와 `.txt` 확장자를 지원하며, 대화형 모드에서는 사용할 수 없습니다. 보고서에는 입력 작업, 도구 호출 과정, 도구 결과, 최종 답변이 포함됩니다.

Agent가 익스플로잇 코드를 작성하면 문법을 확인한 뒤 `workspace/exploit.py`에 저장합니다. `run_exploit` 도구는 해당 파일을 제한 시간 안에 실행하고 종료 코드와 표준 출력/오류를 Agent에 돌려줘서, 실패 원인을 살펴보고 다시 수정할 수 있게 합니다.

### Pwnable 분석 도구

Agent는 아래 도구를 이용해 ELF 바이너리의 익스플로잇 단서를 찾고, 버퍼 오버플로우 입력 길이를 계산할 수 있습니다.

팀 공유용으로 변경 이유와 Agent 실행 흐름, 검증 결과를 [Agent 도구·익스플로잇 변경 설명](docs/agent-tools-explained.md)에 정리했습니다.

- `elf_imports`: ELF가 동적으로 불러오는 함수 목록을 확인합니다. `puts`, `read`, `system` 등 관심 함수 이름으로 필터링할 수 있습니다.
- `elf_relocations`: 함수의 GOT/PLT 재배치 항목과 ELF 내 주소를 확인합니다. PIE 바이너리의 실제 실행 주소를 얻으려면 별도로 런타임 베이스 주소를 알아야 합니다.
- `search_rop_gadgets`: ROPgadget으로 `pop rdi`, `xchg rsp` 같은 가젯을 검색합니다. 기본 깊이 20바이트는 ret2csu의 다중 pop 가젯도 포함하며, 최대 64바이트까지 조정할 수 있습니다.
- `dump_elf_section` / `search_elf_bytes`: `.data`, `.init_array` 내용을 보거나 바이너리 안의 문자열과 가상 주소를 찾습니다.
- `cyclic_pattern`: 4바이트 또는 8바이트 값이 서로 구분되는 패턴을 최대 4096바이트까지 만듭니다.
- `find_cyclic_offset`: 같은 길이와 폭으로 만든 패턴에서 크래시 시점의 레지스터 값을 찾아 오프셋을 계산합니다. `0x...` 레지스터 값은 기본적으로 little-endian으로 해석합니다.
- `debug_binary`: GDB에서 지정한 위치의 레지스터와 명령어를 확인합니다.
- `run_exploit`: 저장된 `exploit.py`를 실행하고 결과를 반환합니다. 실패 출력에 따라 코드를 고친 뒤 다시 실행할 수 있습니다.

일반적인 사용 흐름은 보호기법과 함수·가젯을 확인하고, 필요하면 크래시 오프셋과 레지스터 상태를 측정한 다음 익스플로잇을 작성·실행하는 것입니다. `run_exploit`은 `workspace/exploit.py`만 최대 60초 실행하며, Flag나 성공을 실제 출력에서 확인해야 합니다. 문제 폴더를 통째로 지정하면 Agent가 관련 파일의 폴더 배치를 유지해 복사합니다. 대상 프로그램이 주변 파일을 상대 경로로 읽는다면 익스플로잇에서 `process(elf.path, cwd=os.path.dirname(elf.path))`처럼 실행 디렉터리를 지정해야 합니다. pwntools와 GDB 사용은 Linux/WSL 환경을 권장합니다.

Linux/WSL에서 Python 가상환경을 활성화한 뒤 `pip install -r requirements.txt`를 실행하고, 시스템 도구 `file`, `binutils`, `gdb`를 설치합니다. Ubuntu/WSL에서는 `sudo apt install file binutils gdb`를 사용할 수 있습니다.
