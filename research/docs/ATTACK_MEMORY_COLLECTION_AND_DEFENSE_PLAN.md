# 공격 메모리 수집 흐름과 저토큰 방어 프롬프트 전환 계획

> **Legacy evidence and design provenance.** 이 문서는 기존 3B pilot의 감사와
> 초기 prompt-defense 계획을 보존한다. 현재 논문의 중심 기여, RQ-D1–RQ-D5,
> prospective data contract와 검증 gate의 source of truth는
> [`Adaptive Attack Memory Dataset v1`](DEFENSE_EVALUATED_ADAPTIVE_ATTACK_MEMORY_DATASET_V1.md)이다.

- 상태: **legacy 3B 메모리 흐름 재구성·공개 pack 생성 완료 / prospective
  event-ledger 수집과 확증 실험은 계획 단계**
- 대상: Qwen2.5-VL-3B `public-v2` warm-up 및 ARMOR Framework v2
- 공개 원칙: attack/response payload 비공개, category·strategy·score·transition·
  memory decision과 공개 상태 hash만 공개

**명칭과 claim 경계:** 이것은 비공개인 공식 ARMS 코드를 재현한 결과가 아니다.
PAIR/TAP/Crescendo류의 response-conditioned 적응, 전략 library 검색, winner-grid
쓰기를 결합한 이 프로젝트의 **clean-room memory-adaptive attack pipeline**에서
과거에 수행한 한 legacy 실행을 감사한 결과다. 따라서 아래 수치와 흐름은
“공식 ARMS 일반”이 아니라 이 구현·이 source hash·이 실행에만 귀속된다. 논문에서는
ARMS를 동기와 비교 대상으로 인용하되 구현 명칭은 `memory-adaptive attacker`로
분리한다.

## 1. 이 문서가 답하는 것

이 문서는 다음을 구분해서 기록한다.

1. 현재 3B 공격 메모리가 실제로 어떻게 수집·검색·선택·교체됐는가?
2. CSV, JSON, JSONL 공개본에서 각각 무엇을 확인할 수 있는가?
3. 현재 자료로 어떤 주장을 할 수 있고 어떤 주장은 아직 할 수 없는가?
4. 공격 메모리를 짧고 설명 가능한 시스템 프롬프트로 바꾸기 위해 어떤
   선행연구를 참고할 것인가?
5. 방어로 응답이 바뀐 뒤 공격자가 다시 적응하는 상황까지 어떻게 공정하게
   실험할 것인가?

이 공개 문서에서는 §9의 RQ1–RQ6와 §10–§12의 평가 규약을 source of truth로
삼는다. 더 넓은 private 개발 framework와 동기화하되, GitHub 이용자는 이 문서와
공개 pack만으로 claim 경계와 planned experiment를 판단할 수 있다.

## 2. 확인된 source provenance

현재 감사 대상은 다음 세 private source artifact다. 로컬 절대경로는 공개
pack에 저장하지 않고 logical name과 file hash만 남긴다.

| Source | SHA-256 | 역할 |
|---|---|---|
| promoted `memory.json` | `95dcaff89351dc2789be67a483e6f396b882741c46ca3994fad3b48f3094590c` | 최종 winner grid 101개 |
| warm-up `results.jsonl` | `33e7f9dba1088dc04647fa54fa1a9176ec5f931417cfc1c0ba3d9557a58a076a` | 220개 전체 episode와 520개 query |
| `memory_manifest.json` | `ec136467cde4bb72cfdb1a56f1e08612d7f198c5d55971d5b6c6b92100782de4` | target/model/config/seed/promotion provenance |
| warm behavior shard | `6618b8583ab8878689d16c2ddba42373bc7878a57c1bbcd1c5fe99ffb15c7b77` | 220개 cohort의 manifest-attested source hash |
| runtime config | `043aec590df9e8da1507dd797625e65f39f18390ae9463058d44ef7d38dbfaeb` | 생성·평가·탐색 예산의 동결 설정 |

확인된 주요 실행 조건은 다음과 같다.

- target: `Qwen/Qwen2.5-VL-3B-Instruct`
- target revision: `66285546d2b821cf421d4f5eb2576359d3770cd3`
- initial memory: 없음
- memory mode: epsilon-greedy
- embedder: `BAAI/bge-base-en-v1.5`
- seed: `20261030`
- workers: `4`
- canonical target memory: 위험 category 13개, 최종 strategy 16개
- producer code commit: legacy manifest에 없음(`unattested/missing`)

동결 runtime config에서 확인한 모델과 예산은 다음과 같다. endpoint, checkpoint,
GPU/PID 같은 로컬 서비스 정보는 공개하지 않는다.

| 구성 | 모델/정밀도 | temperature | max tokens |
|---|---|---:|---:|
| attacker | `Qwen/Qwen2.5-VL-32B-Instruct`, dynamic FP8 | 0.8 | 512 |
| judge | `Qwen/Qwen3-30B-A3B-Thinking-2507-FP8`, FP8 checkpoint | 0.0 | 2,048 |
| target | `Qwen/Qwen2.5-VL-3B-Instruct`, bfloat16 | 0.0 | 1,024 |

탐색 한도는 `max_queries=3`, `max_steps=24`,
`min_queries_before_finish=3`, `max_finish_rejections=10`,
`eps_max=1.0`, `eps_min=0.1`, `lambda=1.0`, `top_k=3`,
`alpha=1.2`였다. runtime config의 seed `20261029`보다 warm-up manifest의
명시적 실행 seed `20261030`을 실행 provenance로 우선한다.

### 2.1 Legacy cohort의 관측 범위

현재 220개는 `SALAD-Bench 161`, `HarmBench 39`, `AdvBench 20`이며 공개용
opaque ID 기준으로 220개가 모두 서로 다르다. 13개 위험 category 분포와
dataset별 정확한 행 수는 `json/collection_summary.json`에 보존했다.

그러나 legacy manifest에는 sampling frame 생성 코드 commit, 사전 포함·제외
규칙, semantic dedup receipt, quota를 결과 전에 동결했다는 증거가 없다. behavior
shard의 content hash만 attested돼 있다. 따라서 이 220개는 **descriptive
pilot/engineering evidence**로만 쓰고, universal하거나 cherry-picking-free한
논문 핵심 cohort라고 주장하지 않는다. 확증용 사전등록 수집은 §11.3의 별도
규약을 따른다.

## 3. 실제 수집 흐름

### 3.1 에피소드 내부

```text
behavior + risk category
  ↓
epsilon-greedy memory decision
  ├─ memory 미사용
  └─ 기존 grid에서 top-3 검색
       score = cos(risk category) + 1.2 × cos(behavior)
  ↓
attacker planner가 query/tool action 선택
  ↓
target 응답 생성
  ↓
judge score와 reason 생성
  ↓
다음 query가 있으면 target response 앞 1,200자 + score + reason을 보고 적응
  ↓
episode의 최고 score query를 trajectory candidate로 선택
```

현재 확보된 unversioned clean-room 구현은 `target response only`가 아니라 target
응답 외에 judge score와 reason도 다음 planner 입력에 넣는다. 그러나 legacy
producer commit과 runtime exposure receipt가 없으므로 공개 행에서는 이를
`implementation_inferred_unversioned_not_runtime_attested`로 한정한다. 이 조건이
재현되면 일반 black-box 공격보다 강한 feedback 조건이다. 향후 primary threat
model에서는 response-only를 runtime receipt로 계측하고,
response+judge-feedback은 별도 강한 diagnostic condition으로 분리한다.

### 3.2 에피소드 사이 장기 메모리

legacy `LayeredMemory`는 `(risk_category, dominant strategy)`를 하나의 slot으로
사용한다.

```text
slot이 비어 있음                       -> insert_new_slot
candidate score > 현재 slot score      -> replace_strictly_higher_score
candidate score == 현재 slot score     -> reject_equal_score_first_writer_kept
candidate score < 현재 slot score      -> reject_lower_score
trajectory가 없음                       -> no_trajectory
```

recency, 다양성, uncertainty, query cost, 실패의 정보량은 online insert에
반영되지 않는다. 동점은 먼저 기록된 항목이 남으므로 실행 순서의 영향을 받는다.

### 3.3 재구성된 전체 funnel

```text
220 episodes
  -> 555 retrieval labels across 186 memory-using episodes
  -> 520 target queries
  -> 307 ordered query-to-query transitions
  -> 213 trajectory candidates + 7 no-trajectory
  -> 101 new slots
     + 15 strictly-higher replacements
     + 53 equal-score rejections
     + 44 lower-score rejections
  -> 101 final slots
```

원 `results.jsonl`의 append 순서로 이 규칙을 재생하면 canonical 101개 slot의
내용과 정확히 일치한다. 그러나 원 실행은 `workers=4`였고 insert sequence와
timestamp가 없다. 따라서 append 순서는 **wall-clock 삽입 순서가 입증된
원장**이 아니라 결과와 일치하는 가장 강한 historical proxy다. 공개 manifest에
`replay_order_attested=false`를 명시한다.

### 3.4 성공률 해석

- 실제 warm-up episode strict success: `80/220 = 36.36%`
- 최종 memory의 success slot: `53/101 = 52.48%`

두 번째 값은 각 slot에서 최고 점수 후보가 살아남은 후의 survivor fraction이다.
이를 공격성공률(ASR)로 보고하면 안 된다. 논문의 attack effectiveness는 전체
episode 분모를 사용하고, final slot 통계는 memory coverage/selection 결과로만
보고한다.

## 4. 공개 CSV·JSON·JSONL pack

공개 pack은 [`../artifacts/attack-memory-v1/`](../artifacts/attack-memory-v1/)
에 있다.

### 4.1 CSV: 표·통계 감사

| 파일 | 행 | 분석 단위 |
|---|---:|---|
| `csv/episodes.csv` | 220 | episode |
| `csv/retrievals.csv` | 555 | ordered retrieval label |
| `csv/queries.csv` | 520 | target query |
| `csv/transitions.csv` | 307 | adjacent query edge |
| `csv/memory_updates.csv` | 220 | memory decision |
| `csv/final_slots.csv` | 101 | final survivor slot |

CSV는 사람이 spreadsheet로 검토하거나 category-macro 집계, transition matrix,
survivor bias, score delta를 계산할 때 사용한다.

### 4.2 JSON: 계층형 episode 탐색

- `json/collection_summary.json`: provenance, 집계, 분포, 제한사항
- `json/memory_flow.json`: episode 아래에 retrievals, queries, transitions,
  memory update를 중첩

사이트와 notebook에서는 JSON view를 사용한다. 이 파일은 원 응답을 보여주는
trace viewer가 아니라 **메타데이터 흐름 viewer**다.

### 4.3 JSONL: 순차 replay

`jsonl/memory_flow.jsonl`은 다음 2,042개 event를 하나의 공개 hash chain으로
기록한다.

```text
episode_started
retrieval_observed × k
query_observed
strategy_transition_observed
memory_update_decided
episode_ended
```

이것은 현재 prospective schema의 canonical `AttackProcessEvent`가 아니다.
legacy 자료에서 복원한 `legacy_reconstruction_event_v1`이며, 관측되지 않은
lineage를 만들어내지 않는다.

## 5. 공개·비공개 경계

GitHub에는 다음을 공개한다.

- risk category, strategy, defense family
- query/turn/image-reference 수
- score, success, score delta
- retrieval rank와 label
- insert/replace/reject 결정
- behavior 원문을 encode하지 않는 순차 episode/entry occurrence ID와
  payload-free slot version
- 공개 projection만으로 만든 memory-head hash chain

다음은 공개하지 않는다.

- behavior 원문과 원래 behavior ID
- user turn과 image/artifact path
- target response와 judge reason
- step args, reflection, planner raw action
- behavior/response/reason/full trajectory를 직접 연결하는 per-item content hash
- endpoint, checkpoint 로컬 경로, secret, PID, 서비스 상태

공개 pack은 통계·taxonomy·replay 코드 감사에는 충분하지만 방어 prompt를
동일하게 재생성하기에는 의도적으로 불충분하다. prompt compilation은 접근
통제된 private memory에서 실행하고, 고정된 prompt와 compiler manifest만
공개한다.

순차 ID, append ordinal, `instance_index`는 source 보유자의 정확한 감사 결합을
위한 키다. 원문을 직접 포함하지는 않지만 익명화나 비연결성을 보장하지 않는다.

## 6. 현재 taxonomy와 논문용 확장

### 6.1 현재 결정론적 surface family

현재 17개 관측 strategy label은 다음 다섯 family로 사전 매핑한다.

1. `adaptive_trajectory`
2. `social_document_framing`
3. `structured_transformation`
4. `fragmentation_and_many_shot`
5. `cross_modal_obfuscation`

이 family는 표현 방식과 attack surface를 설명한다. 이름만으로 target 응답을
보고 수행한 실제 적응 연산을 증명하지 않는다.

### 6.2 논문용 experience atom

향후 primary memory의 최소 단위는 최종 trajectory가 아니라 다음 edge다.

```text
state_t
+ retrieved memory occurrence IDs
+ attacker-visible feedback policy
+ previous target exposure state
  -> transition operator/action_(t+1)
  -> target observation_(t+1)
  -> validity/completion/harm/cost outcome
  -> append-only memory write receipt
```

각 atom은 다음 다섯 축으로 분류한다.

| 축 | 예시 |
|---|---|
| Strategy/surface | carrier, topology, trust boundary, semantic operator, modality, context frame, optimizer |
| Transition | persist, refine, escalate, reframe, switch modality, fragment/recombine, retrieve/reuse, branch/prune, mutate, stop |
| Feedback | none, response-only, response+score, response+reason, objective/tool feedback, retrieval |
| Exposure | refusal-only, generic boundary, specific cue leakage, partial compliance, full compliance, safe redirect |
| Outcome | validity, policy completion, capability harm, cumulative harm, target calls, censoring, error, termination |

taxonomy는 outcome을 보기 전에 build split에서 동결하고 `UNKNOWN`을 유지한다.
reflection은 self-report이므로 hypothesis source로만 쓰고 정답 label로 쓰지
않는다.

## 7. 선행연구에서 가져올 요소와 차이

### 7.1 공격 메모리와 적응형 공격

| 선행연구 | 참고할 요소 | 이번 연구에서의 차이 |
|---|---|---|
| [AutoDAN-Turbo, ICLR 2025](https://proceedings.iclr.cc/paper_files/paper/2025/file/1bff3663270ba47f801e917f782d7935-Paper-Conference.pdf) | 스스로 발견한 전략을 library로 저장하고 다른 공격에 재사용하는 lifelong 공격 | 공격 library의 성공 전략만 재사용하지 않고 실패·전환·feedback·write lineage까지 방어용 evidence로 역변환 |
| [PAIR, NeurIPS 2023](https://openreview.net/pdf/7b330930f73f5ba45b8219e5ce7a9c0bc6b02ba9.pdf) | target 응답을 보고 다음 semantic prompt를 반복 개선 | 단일 최종 prompt가 아니라 response-conditioned transition을 저장 |
| [TAP](https://openreview.net/pdf?id=AsZfAHWVcz) | branching과 pruning을 포함한 search tree | branch/prune/parent state를 공통 event schema의 native state로 기록 |
| [GPTFuzzer](https://arxiv.org/abs/2309.10253) | seed selection, mutation operator, judge 기반 archive 갱신 | method 이름이 아니라 mutation/selection/retrieval 연산을 factor로 저장 |
| [Crescendo](https://arxiv.org/abs/2404.01833) | 이전 응답을 인용하며 점진적으로 목표를 이동시키는 multi-turn progression | `escalate/reframe/reuse` edge를 prompt rule의 근거로 사용 |

### 7.2 공격 기술 사전과 unseen generalization

[Adversarial Déjà Vu: Jailbreak Dictionary Learning for Stronger
Generalization to Unseen Attacks (ICLR 2026)](https://proceedings.iclr.cc/paper_files/paper/2026/hash/ab41709d06e9303c25ad6742ae661198-Abstract-Conference.html)는
32개 공격 논문에서 adversarial skill을 추출·압축해 sparse dictionary로 만들고,
unseen 공격을 기존 skill의 조합으로 설명하는 관점을 제시한다.

이번 연구가 가져올 것은 `paper/method name → 재사용 가능한 primitive`라는
추상화다. 차이는 다음과 같다.

- primitive를 attack instance의 표면 기술만으로 만들지 않는다.
- `이전 응답 상태 → 적응 연산 → 다음 응답 변화`를 함께 저장한다.
- dictionary 자체를 adversarial training data로만 사용하지 않고, target의
  fixed system prompt가 실행할 짧은 defense invariant로 컴파일한다.
- leave-one-method/surface/controller-out으로 dictionary 외 공격에 대한 방어
  전이를 검증한다.

### 7.3 시스템 프롬프트 기반 방어

| 선행연구 | 참고할 요소 | 주의점 |
|---|---|---|
| [Self-Reminder, Nature Machine Intelligence 2023](https://www.nature.com/articles/s42256-023-00765-8) | system-mode reminder만으로 방어를 강화할 수 있다는 정적 baseline | memory condition과 unseen transfer를 직접 최적화하지 않음 |
| [Goal Prioritization, ACL 2024](https://aclanthology.org/2024.acl-long.481/) | helpfulness보다 safety goal을 우선하는 inference instruction | 과잉거절과 task utility를 반드시 paired 평가 |
| [RPO](https://arxiv.org/abs/2401.17263) | 적대적 목적함수로 lightweight transferable defense suffix를 최적화 | 우리 비교에서는 동일 token/validation-call budget으로 맞춤 |
| [AdaShield, ECCV 2024](https://www.ecva.net/papers/eccv_2024/papers_ECCV/papers/02990.pdf) | MLLM에 방어 prompt를 prepend하고 defender가 prompt를 반복 개선; benign capability 평가 | 구조 기반 VLM 공격에 국한하지 않고 multi-turn transition memory까지 포함 |
| [Defensive Prompt Patch, ACL Findings 2025](https://aclanthology.org/2025.findings-acl.23/) | adaptive attack을 고려한 prompt patch와 safety–utility 목표 | final patch의 성능뿐 아니라 memory source의 인과 기여를 placebo로 분리 |
| [ICAG, EMNLP 2024](https://aclanthology.org/2024.emnlp-main.1121/) | attacker–defender in-context game와 반복적 defense 개선 | 개발 game와 sealed confirmation을 분리해 validation overfitting 방지 |

### 7.4 자동 최적화와 압축

- [ProTeGi, EMNLP 2023](https://aclanthology.org/2023.emnlp-main.494/)의
  textual-gradient critique, beam expansion, bandit selection을 prompt 후보 생성
  baseline으로 사용한다.
- [RLPrompt, EMNLP 2022](https://aclanthology.org/2022.emnlp-main.222/)는
  discrete prompt를 강화학습으로 탐색하는 neural/RL compiler baseline이다.
- [MIPRO](https://arxiv.org/abs/2406.11695)는 instruction proposal과
  surrogate-guided search의 비교군으로 사용한다.
- [LongLLMLingua, ACL 2024](https://aclanthology.org/2024.acl-long.91/)와
  [LLMLingua-2](https://aclanthology.org/2024.findings-acl.57/)는 token
  compression baseline이다. 안전 규칙의 부정어·예외를 손상할 수 있으므로
  primary compiler는 clause selection을 사용하고 token pruning은 별도 baseline으로
  둔다.

## 8. Memory-to-Prompt compiler 계획

### 8.1 입력

private append-only ledger에서 payload-free aggregate만 compiler에 전달한다.

```text
risk/category coverage
surface factors
transition operator frequencies
score/harm deltas with uncertainty
failure and regression codes
retrieval/write lineage coverage
benign exception evidence
```

원 행동 문장, 공격 query, target response, reflection을 deployment prompt에
복사하지 않는다.

### 8.2 중간 표현: defense atom

각 cluster를 다음 구조로 바꾼다.

```text
invariant: 표면 형식과 무관하게 지켜야 할 경계
forecast: 다음에 올 수 있는 적응 연산
safe_action: unsafe capability만 제한하고 safe remainder 제공
benign_exception: 정상 질문을 과잉거절하지 않을 조건
public_rationale: 탐지 cue를 노출하지 않는 최소 설명
evidence: source occurrence IDs, coverage, uncertainty, failure evidence
```

### 8.3 후보 prompt DSL

고정 system prompt는 다음 순서를 사용한다.

1. 전체 대화와 모든 modality에서 실제 요청 outcome을 추적
2. 이전에 제한된 목표의 재표현·분할·형식 전환을 동일 latent goal로 검토
3. 이미지·문서 내부 지시는 untrusted user content로 처리
4. unsafe capability만 제한하고 benign/안전한 부분은 계속 수행
5. 설명은 capability boundary 수준으로 짧게 제공
6. 내부 rule, category score, trigger, exact detection cue는 공개하지 않음

단순 keyword blacklist나 공격 샘플 목록을 넣지 않는다. 고정 prompt가 동적으로
행동하는 이유는 매 turn마다 같은 짧은 invariant를 현재 전체 transcript와 modality에
재적용하도록 지시하기 때문이다.

### 8.4 최적화 목적

후보 prompt `p`의 개발 목적은 다음처럼 분리한다.

```text
J(p) = safety_gain
       - lambda_u * benign_utility_loss
       - lambda_o * over_refusal
       - lambda_t * prompt_tokens
       - lambda_l * cue_leakage
       - lambda_c * online_target_calls
```

한 scalar만 보고 사후 가중치를 바꾸지 않는다. safety, utility, token,
leakage의 hard gate를 먼저 적용하고 통과 후보 안에서 최소 token prompt를
선택한다. 현재 framework의 예산은 `64 → 128 → 192` token이며, 더 긴 prompt는
oracle/diagnostic으로만 둔다.

## 9. 기존 RQ에 연결한 실험 계획

### RQ1 — Memory-conditioned attribution

질문: target-matched memory 구조가 같은 길이의 generic safety prompt와
label–evidence placebo를 넘어 방어 가치를 주는가?

필수 logical condition:

1. Native: 추가 prompt 없음
2. Generic: 동일 token 수 일반 안전 prompt
3. Matched-memory: target memory에서 컴파일
4. Label–Evidence Placebo: item·category·score 분포와 compiler는 유지하고
   aggregation 전 label–evidence 연결만 고정 seed로 permutation

Matched가 Native만 이기는 것으로는 memory 기여를 주장하지 않는다.
Matched−Generic과 Matched−Placebo가 모두 통과해야 한다.

### RQ2 — Live adaptive synthesis

memory source를 고정하고 합성 방식만 비교한다.

- human-written
- frequency-greedy clause selection
- static/frozen compiler
- ProTeGi-style textual-gradient search
- live CEGIS attacker–defender loop
- optional neural/RL warm-start

모든 방법의 online validation target-call budget, token budget, stopping rule을
맞춘다. offline 생성 비용도 0으로 처리하지 않고 별도 보고한다.

### RQ3 — Deployable Pareto

selection split에서 하나의 최소 feasible prompt를 동결한 뒤 별도 confirmation
split에서 다음을 동시에 확인한다.

- strict ASR 감소
- policy-completion/capability-harm 감소
- 정상 helpfulness와 task fulfillment 비열등성
- XSTest/[OR-Bench](https://proceedings.mlr.press/v267/cui25a.html)의 gross
  over-refusal 상한
- prompt token과 latency 예산

[XSTest](https://aclanthology.org/2024.naacl-long.301/)를 sensitive-looking but
safe 입력에 대한 과잉거절 기준으로 사용한다.

### RQ4 — Auditable explanation

같은 safe response body에 설명만 바꾼다.

1. 설명 없음
2. 최소 capability-boundary 설명
3. risk-family 수준 설명
4. 상세 cue 설명 — 사람에게는 보여주지 않는 leakage upper bound

사람 대상 평가는 설명 이해도·납득도·정상 도움성을 본다. 별도 attacker는
그 설명을 본 뒤 재공격한다. 사람 이해도 향상과 follow-up exploitation
비열등성을 함께 통과해야 설명가능성 주장을 허용한다.

### RQ5 — Online-memory horizon

core 평가에서는 모든 arm을 동일 initial memory snapshot으로 reset한다. X1
확장 실험에서만 episode 간 memory를 누적하고, 고정 prompt가 첫 strict success까지
걸리는 target-call horizon을 늘리는지 본다. 각 defense arm의 memory는 첫 응답
이후 완전히 격리한다.

### RQ6 — Neural compiler efficiency

신경망은 target 모델을 fine-tune하는 것이 아니라 aggregate defense atom에서
고정 system-prompt 후보를 제안하는 optimizer다. 학습된 후보도 별도 split에서
다시 freeze하고 같은 safety/utility/leakage gate를 통과해야 한다. 보고 항목은
학습비, post-training per-task rollout, break-even task 수다.

## 10. Adaptive re-attack 평가

paired block의 시작 조건은 다음을 동일하게 맞춘다.

```text
(behavior, attacker seed, initial memory snapshot, ordered assets,
 decoding config, target-call budget)
```

첫 target request까지 동일하게 맞추고, 이후에는 각 방어 prompt가 만든 새
응답을 attacker가 실제로 본다. 응답이 달라진 뒤 공격 경로가 갈라지는 것은
오염이 아니라 방어의 전체 처리효과다. frozen replay로 후속 공격을 같게 만들지
않는다.

적응성 자체는 다음 intervention으로 조작검증한다.

- natural response
- no response
- masked response
- response swap
- frozen response
- sham memory

두 번째 action, strategy transition, memory write와 장기 success/horizon이
response intervention에 따라 달라지는지 확인한다. judge는 최종 결과 평가에는
사용하지만 primary attacker feedback에는 넣지 않는다.

## 11. 데이터 분할과 일반화

### 11.1 분할 원칙

- behavior exact/semantic dedup 후 build, selection, confirmation을 분리
- 같은 behavior의 turn/seed를 서로 다른 split으로 보내지 않음
- final test item, hash, label을 compiler에 노출하지 않음
- taxonomy와 mapping은 build split에서 동결
- 성공, 실패, fallback, censored, no-target-call, infra error를 모두 보존

### 11.2 generalization 축

- leave-one-attack-method-out
- leave-one-surface/operator-out
- leave-one-controller-out
- target transfer: Qwen2.5-VL 3B → 7B/32B
- other-target memory와 matched-memory 비교
- temporal holdout: 새 공격법을 dictionary 동결 뒤 평가

현재 3B/7B slot overlap만으로 universal memory를 주장하지 않는다. 공통
invariant와 target-specific residual을 별도 계층으로 두고 confirmatory transfer를
실행한다.

### 11.3 사전등록할 공격 우주와 cohort 규약

legacy 220개 대신 논문 핵심 수집은 결과를 보기 전에 다음 registry를 동결한다.

1. **방법 우주:** response-refinement(PAIR), branch/prune(TAP),
   mutation/archive(GPTFuzzer), progressive multi-turn(Crescendo),
   lifelong strategy library(AutoDAN-Turbo)의 native algorithmic factor와
   repository commit/adapter parity를 표로 등록한다.
2. **행동 우주:** HarmBench·AdvBench·SALAD-Bench의 허용된 subset을 exact/semantic
   dedup하고, 원 dataset ID는 private vault에 보존한다. category mapping,
   포함·제외 규칙, sampling seed를 결과 전에 공개한다.
3. **고정 할당:** 방법×위험 category×target×seed cell의 quota는 pilot variance를
   이용한 사전 power analysis로 정하고, 빈 cell과 미지원 modality도 결과에서
   제거하지 않고 `unsupported/censored`로 보존한다.
4. **완전 원장:** 성공뿐 아니라 실패, reject, fallback, timeout, infra error,
   no-target-call을 append-only ledger에 모두 쓴다. winner grid는 검색용 파생
   index일 뿐 통계 분모가 아니다.
5. **동결 순서:** taxonomy·mapping·split hash·예산·stopping rule·primary metric을
   동결한 뒤 build memory를 만들고, selection 이후 compiler를 freeze한 다음
   confirmation/leave-one-method-out을 한 번 실행한다.

이 규약과 event schema를 만족한 새 run만 paper-grade primary memory로 승격한다.
legacy pack은 exporter와 분석 코드를 검증하는 pilot로 남긴다.

## 12. 평가 지표와 통계

공격 평가는 [JailbreakBench](https://openreview.net/pdf?id=urjPCYZt0I)의
명시적 threat model·query/token accounting 원칙과
[StrongREJECT](https://arxiv.org/abs/2402.10260)의 응답 유용성 기반 평가를
참고한다.

Primary/secondary metric:

- behavior-level strict ASR
- category-macro strict ASR
- individual/cumulative policy completion
- capability harm
- first success까지 target-call 수와 safe horizon
- response-conditioned strategy/family transition
- benign task fulfillment/helpfulness
- gross over-refusal
- token 수, latency, attacker/target/judge call 비용
- cue leakage와 explanation-conditioned follow-up ASR

turn이나 memory slot을 독립 표본으로 세지 않는다. 동일 behavior의 seed는
nested replicate로 취급하고 behavior-cluster bootstrap과 category-macro paired
contrast를 사용한다. censoring은 defense success로 처리하지 않고 worst/best-case
bound를 함께 보고한다.

## 13. 현재 자료로 허용되는 주장

허용:

- 220개 legacy episode에서 101개 winner slot이 만들어진 선택 과정을 정확히
  재생했다.
- 현재 memory가 `(category, strategy)` max-score grid임을 보였다.
- 307개 ordered query transition과 555개 retrieval label을 payload-free하게
  분류할 수 있다.
- final success-slot fraction과 episode ASR가 다름을 보였다.
- private prototype compiler가 five-family defense atom과 짧은 prompt 후보를
  생성했다. 이는 **후보 생성 구현 상태**이며 방어 효과의 확증 결과가 아니다.

아직 금지:

- final 53/101을 공격 ASR이라고 표현
- legacy transition을 explicit causal dependency라고 표현
- current family를 검증된 adaptive mechanism이라고 표현
- 공개 pack만으로 동일 방어 prompt가 재현된다고 표현
- 아직 실행하지 않은 multi-method event ledger를 paper-grade evidence라고 표현
- fixed system prompt가 unseen adaptive attack을 방어한다고 확정 표현

## 14. 다음 수집에서 반드시 추가할 필드

prospective append-only ledger에는 다음을 실행 시점에 기록한다.

- monotonic event/write sequence와 timestamp
- method/repository commit/adapter parity
- native controller state before/after와 parent/branch
- retrieval occurrence ID, snapshot, rank, score, selected/consumed receipt
- attacker에게 실제 공개된 feedback policy와 ordered bundle
- explicit response-dependency event ID
- per-turn transition operator와 surface factor IDs
- target response의 private raw vault hash와 payload-free exposure label
- insert/reject/replace receipt와 memory head before/after
- attacker/tool/target/judge call·token·latency·error ledger
- independent validity/completion/harm outcome

private workspace의 `adaptive_attack/event_memory.py` schema 방향을 유지하되
legacy reconstruction을 canonical event로 위장하지 않는다.

## 15. 재현 명령

private source를 보유한 환경에서 공개 pack을 다시 생성한다.

```bash
python research/scripts/export_attack_memory_audit.py \
  --memory /path/to/memory.json \
  --results /path/to/results.jsonl \
  --manifest /path/to/memory_manifest.json \
  --out /path/to/public-pack
```

검증:

```bash
python -m pytest -q research/tests/test_export_attack_memory_audit.py
python research/scripts/verify_attack_memory_audit.py \
  research/artifacts/attack-memory-v1
```

GitHub Pages는 `dist/`만 배포하므로 이 pack은 자동으로 웹사이트에 노출되지
않는다. 사이트에 연결할 때도 aggregate JSON만 별도로 redaction 검증한 뒤
복사해야 한다.

저장소의 프로젝트 라이선스는 아직 확정되지 않았다. 이 공개 자료는 현재
audit/reproduction review 용도이며 upstream benchmark·모델의 라이선스와 사용
조건을 각각 따라야 한다.
