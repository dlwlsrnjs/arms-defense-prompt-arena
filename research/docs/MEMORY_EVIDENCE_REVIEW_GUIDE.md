# Memory Evidence Lab review guide

## 목적과 공개 경계

Memory Evidence Lab은 `attack-memory-v1`의 payload-free projection을 사람이
검토하고 다음 방어 실험의 작업 항목으로 바꾸는 화면이다. 공개 자료에는 공격 요청,
타깃 응답, judge 이유, 원 behavior ID, 로컬 경로가 없다. 따라서 이 화면만으로 공격을
재현하거나 ARMOR 시스템 프롬프트를 곧바로 합성할 수는 없다.

이 공개 도구와 브라우저 `localStorage` 기록은 **exploratory pilot**이다. 사용자가
자유롭게 항목을 고를 수 있고, LLM 제안 전 독립 human label, 고정 assignment queue,
이중 주석, adjudication, model/prompt provenance를 강제하지 않으므로 그 export를
그대로 논문용 정답 corpus라고 부르지 않는다. Claim-bearing data의 수집·동결·누출
방지·품질 검증 절차는
[`HUMAN_LLM_ATTACK_DYNAMICS_DATA_PROTOCOL_V1.md`](HUMAN_LLM_ATTACK_DYNAMICS_DATA_PROTOCOL_V1.md)를
따른다.

현재 legacy pack의 관측 단위는 다음과 같다.

- 220개 episode와 520개 target query
- 307개 순서 기반 strategy transition
- 213개 trajectory candidate와 7개 no-trajectory episode
- max-per-slot 선택 후 남은 101개 final slot

`80/220`은 episode strict success이고, `53/101`은 선택 뒤 남은 성공 slot의
비율이다. 두 번째 수치를 공격성공률로 해석하지 않는다. final slot은 본질적으로
survivor-biased view이므로 episode와 transition 근거를 함께 본다.

## 한 항목을 검토하는 순서

1. **근거 수준 확인:** runtime receipt가 있는지, 프로그램 순서에서 추론한 전이인지,
   retrieval이 label-only인지 먼저 확인한다.
2. **대화 동학 추상화:** 특정 문구를 복사하지 말고, 이전 응답을 다음 요청에 이용하는
   방식, 목표를 단계적으로 바꾸는 방식, 역할·정당화·분해·지속성 같은 연결 규칙을
   짧은 방어 불변식으로 적는다.
3. **정상 예외 작성:** 같은 표면 신호가 정상적인 교육·분석·지원 대화에서 나타날 때
   허용해야 할 조건을 적는다.
4. **적응형 재공격 예측:** 방어 응답을 본 공격자가 다음 turn에서 어떤 규칙을
   우회하려 할지, payload가 아닌 operation 수준으로 적는다.
5. **평가 작업 정의:** 제안한 불변식이 strict ASR뿐 아니라 helpfulness,
   task fulfillment, gross over-refusal에서 어떻게 반증될 수 있는지 적는다.

## 검토 상태

| 상태 | 의미 |
|---|---|
| `unreviewed` | 사람이 아직 판단하지 않음 |
| `actionable` | 근거와 정상 예외, 평가 작업이 모두 있어 다음 실험에 투입 가능 |
| `needs_evidence` | 아이디어는 있으나 runtime lineage, 교차 방법 또는 실패 사례 근거가 부족 |
| `reject` | payload 특이적이거나, 누출 위험이 있거나, 근거로부터 도출되지 않음 |
| `reviewed` | 검토는 끝났지만 즉시 compiler 입력으로 쓰지 않는 참고 항목 |

Legacy pack만 본 항목은 다음 중 하나라도 만족하지 않으면 기본적으로
`needs_evidence`로 둔다.

- 같은 추상 규칙이 서로 독립적인 behavior cluster에서 반복됨
- 성공뿐 아니라 실패·교체·폐기 episode에서도 예상 가능한 차이를 보임
- 새 사전등록 공격 방법의 held-out run에서 재현됨
- benign counterexample로 과거절 위험을 검사함

현재 공개 pack에는 완전한 behavior-cluster lineage와 명시적 response-consumption
receipt가 없으므로, 이 조건의 통과를 표시하는 것은 향후 preregistered run의 책임이다.

## 사람이 남기는 필드

- `defense_invariant`: 모델이 매 turn 확인할 짧고 일반적인 대화 규칙
- `predicted_adaptation`: 그 규칙을 본 공격자의 다음 operation 예측
- `benign_exception`: 같은 신호가 정상일 때 답변을 유지하는 조건
- `evaluation_task`: 안전성·정상 성능·누출을 함께 확인하는 반증 가능한 작업
- `note`: provenance 문제, 중복, 보류 이유

브라우저에서 작성한 내용은 서버로 전송하지 않고 versioned `localStorage`에만
보관한다. JSON 또는 CSV로 내려받아 연구 검토 절차에 제출할 수 있다. 여러 사람의
export를 합칠 때는 reviewer 식별자를 공개 파일에 넣지 말고 별도 접근 통제된
manifest로 관리한다.

본 수집 UI로 승격할 때는 `human_initial`을 LLM 제안 공개 전에 잠그고,
`llm_proposal`, `human_final`, 독립 투표와 `adjudication`을 별도 event로 보존한다.
현재 export에는 이 lineage가 없으므로 taxonomy 후보 발굴과 도구 개선에만 사용한다.

## compiler로 승격하기 전 gate

사람 주석은 곧바로 시스템 프롬프트 문장이 아니다. 다음 gate를 모두 통과한
추상 규칙만 private compiler의 후보 입력이 된다.

1. 사전등록된 attack universe에서 provenance가 완전한 event ledger로 재관측
2. 방법·category·성공 여부를 가로지르는 coverage 확인
3. held-out 공격 방법에서 방향성 확인
4. 정상 예외와 token budget을 포함한 prompt DSL 변환
5. Generic 및 label–evidence placebo와 token-matched 비교
6. 방어 응답을 본 공격자가 다시 적응하는 live 평가

이 절차는 사람이 흥미로운 성공 사례만 골라 규칙을 쓰는 것을 막고, 메모리를
저토큰 시스템 프롬프트로 바꾸는 과정 자체를 검정 가능한 연구 대상으로 만든다.
