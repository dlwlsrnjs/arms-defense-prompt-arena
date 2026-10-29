# DEFENDER VS ARMS

DEFENDER VS ARMS는 메모리 기반 적응형 ARMS 공격자에 맞서, 사람이 작성한 시스템 프롬프트와 학습 에이전트가 작성한 시스템 프롬프트를 동일한 시작 조건에서 비교하기 위한 연구 인터페이스입니다.

이 저장소는 ARMS 논문을 참고한 clean-room 재구현 프로젝트의 공개 사이트입니다. 공식 ARMS upstream 코드가 아닙니다.

**Live demo:** https://dlwlsrnjs.github.io/arms-defense-prompt-arena/

## 무엇을 보여주나요?

- Qwen2.5-VL 3B, 7B, 32B 타깃별 public-v2 사전 메모리 준비 상태
- 왼쪽 메뉴에서 개요·모델/데이터·Adaptive Duel·결과·방법론을 전환하는 5-view 대시보드
- 사람이 작성하는 방어 시스템 프롬프트와 재현 가능한 실행 계획
- 방어 프롬프트 이후 생성되는 새 타깃 응답과 그 결과에 적응하는 ARMS의 순차적 변화
- 기존 합성 데이터 결과와 public-v2 결과의 명확한 분리
- 공격 성공률뿐 아니라 정상 응답과 과잉 거부를 함께 보는 평가 프로토콜

사이트에는 유해 원문, 공격 payload, 타깃 모델의 원문 응답을 공개하지 않습니다. 표시되는 결과는 집계값과 provenance 정보로 제한됩니다.

## DEFENDER VS ARMS 방법론

DEFENDER VS ARMS는 고정된 과거 입력을 다시 적용하는 방식이 아닙니다. 방어 프롬프트가 바뀌면 타깃 모델이 새 응답을 생성하고, ARMS는 그 새 결과를 관찰해 타깃별 메모리를 갱신한 뒤 다음 공격을 다시 선택합니다.

1. **Initialize** — 각 branch는 같은 타깃 체크포인트, 사전 준비된 ARMS 메모리, 시나리오 pool에서 출발합니다.
2. **Defend** — 사람 또는 학습 에이전트가 타깃의 시스템 프롬프트 하나를 설치합니다.
3. **Attack & Respond** — ARMS가 현재 메모리를 검색해 다음 공격을 구성하고, 방어 프롬프트가 적용된 타깃이 새 응답을 생성합니다.
4. **Observe & Update** — 안전성·유틸리티 판정의 추상 신호를 ARMS가 관찰하고, 원문 대신 안전한 전략·결과 메타데이터를 메모리에 기록합니다.
5. **Adapt** — 갱신된 메모리를 조건으로 다음 공격 전략을 선택하며 closed loop를 계속합니다.

사람·에이전트·무방어 branch는 동일한 사전 준비 상태를 복제해 시작하지만, 첫 상호작용 이후의 응답·메모리·공격 경로는 각 branch에서 독립적으로 진화합니다. 따라서 방어 프롬프트의 효과는 이후 공격자의 적응까지 포함해 측정합니다.

### 방어자 관찰 모드

- **OPEN MEMORY** — 방어자는 redaction된 ARMS 메모리 검색 결과와 현재 전략 메타데이터를 실시간으로 보고 시스템 프롬프트를 작성합니다.
- **BLIND DEFENSE** — 방어자는 ARMS 메모리와 전략 상태를 보지 못한 채 동일한 시스템 프롬프트 인터페이스로 방어합니다.

두 모드에서 공격자의 동작은 같습니다. ARMS는 매번 새 타깃 응답의 판정 신호를 관찰하고 메모리를 갱신한 뒤 다음 공격을 적응시킵니다. 모드 간 유일한 실험 차이는 방어자에게 공격자 메모리·전략이 보이는지 여부입니다.

브라우저의 게임형 인터페이스는 이 상태 전이를 설명하는 안전한 deterministic **simulator estimate**입니다. 브라우저에서 실제 모델 추론을 실행하지 않으며 공식 ASR도 생성하지 않습니다. 공식 GPU/Qwen 수치는 private runner가 새 응답과 메모리 갱신을 순차 실행한 결과만 별도 영역에 표시합니다. 공개 VLM 입력은 시나리오 구조만 보존하고 위험 목표와 실행 가능한 내용을 redaction한 fixture입니다.

## 공개 벤치마크 프로토콜

| 역할 | 데이터셋 |
| --- | --- |
| Memory pre-warm | AdvBench, HarmBench validation, SALAD-Bench stratified sample |
| Adaptive text scenarios | HarmBench test, StrongREJECT, JailbreakBench comparison track |
| Adaptive VLM scenarios | MM-SafetyBench Tiny |
| Benign utility | XSTest, OR-Bench hard benign subset |

평가용 시나리오 pool은 사전 메모리 준비 및 방어 학습 자료와 절차적으로 분리합니다. 그러나 평가가 시작된 뒤에는 매 새 타깃 응답의 판정 결과가 해당 branch의 ARMS 메모리를 갱신하며, 다음 공격은 그 최신 상태에 적응합니다. 여기서 held-out은 시나리오 seed의 절차적 분리를 뜻하며, 타깃 모델의 사전학습 미포함을 보장하지 않습니다.

## 로컬에서 보기

별도 빌드 과정은 없습니다. 저장소 루트에서 정적 서버를 실행한 뒤 `dist/`를 열면 됩니다.

```bash
python3 -m http.server 8000 --directory dist
```

브라우저에서 `http://localhost:8000`으로 접속합니다. `file://`로 직접 열면 상태 JSON 요청이 브라우저 보안 정책에 의해 차단될 수 있습니다.

공개 자산·DOM 계약·redaction 경계는 다음 명령으로 확인합니다.

```bash
node scripts/validate-site.cjs
```

## 상태 데이터

사이트 런타임은 공식 상태용 `dist/data/arena-status.json`과 안전한 폐쇄 루프 게임용 `dist/data/adaptive-scenarios.json`을 읽습니다. `dist/data/memduel-traces.json`은 이전 공개 schema와의 호환성 검증용이며, 내용과 메타데이터는 현재의 adaptive scenario seed 의미로 갱신되어 있습니다. 공식 데이터가 없거나 아직 준비되지 않은 필드는 숫자를 추정하지 않고 `pending`으로 표시합니다.

공개 상태 파일에는 다음 정보만 포함해야 합니다.

- benchmark pack의 aggregate provenance와 row count
- 타깃별 사전 메모리 readiness와 SHA-256
- closed-loop post-warm 집계 결과와 상태 전이 메타데이터
- historical synthetic 결과라는 명시적 provenance

로컬 체크포인트 경로, 비밀값, 유해 원문 또는 개별 모델 응답을 커밋하지 마세요.

## GitHub Pages 배포

`.github/workflows/pages.yml`은 `main` 브랜치에 push될 때 `dist/`를 그대로 GitHub Pages artifact로 배포합니다. 공개 저장소를 만든 뒤 저장소의 **Settings → Pages → Source**를 **GitHub Actions**로 선택하면 됩니다.

워크플로는 GitHub 공식 Pages Actions만 사용합니다.

- `actions/configure-pages`
- `actions/upload-pages-artifact`
- `actions/deploy-pages`

이 공개 저장소에는 GitHub Pages 배포에 필요한 파일만 포함하며, 별도 호스팅 서비스의 내부 프로젝트 식별자는 포함하지 않습니다.

## 저장소 구조

```text
dist/                         배포되는 정적 사이트
  data/arena-status.json      공개 가능한 집계 상태
  data/adaptive-scenarios.json  브라우저 폐쇄 루프 시뮬레이터 입력
  data/memduel-traces.json    이전 schema 호환용 redacted adaptive seeds
.github/workflows/pages.yml   GitHub Pages 배포
scripts/validate-site.cjs     공개 자산·DOM·fixture 검증
```

## 라이선스와 데이터셋

이 저장소에는 벤치마크 원문 데이터가 아니라 집계 메타데이터만 포함됩니다. 각 벤치마크의 이름과 출처는 원 프로젝트의 라이선스 및 사용 조건을 따르며, 프로젝트 전체에 적용할 오픈소스 라이선스는 아직 지정하지 않았습니다.
