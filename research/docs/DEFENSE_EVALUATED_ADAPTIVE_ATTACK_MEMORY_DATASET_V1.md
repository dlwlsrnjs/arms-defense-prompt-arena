# Adaptive Attack Memory Dataset v1

## Defense-evaluation-ready dataset protocol and paper framing

## 결정 요약

이 프로젝트의 중심 기여는 특정 방어 prompt compiler가 아니라, **방어에 사용할 수
있는지까지 검증하는 적응형 공격 메모리 데이터셋과 benchmark protocol**로 둔다.

작업명은 `Adaptive Attack Memory Dataset v1`, 약칭은 `AAMD-v1`이다. G6 전에는
`defense-evaluation-ready`라고만 부른다. G6 sealed evaluation을 완료한 뒤에는 결과와
무관하게 `defense-evaluated`, 사전등록된 안전성 개선과 정상 성능 비열등성을 모두
만족한 뒤에만 `defense-validated`라는 표현을 사용한다.
결과가 null 또는 negative여도 효과가 없었던 메모리와 불확실성을 포함한 검증 corpus로서
데이터셋 기여는 남는다.

논문의 중심 문장은 다음과 같다.

> AAMD-v1 records how heterogeneous adaptive attackers write, retain, retrieve,
> consume, and revise attack memory, validates whether those records causally
> affect later attack behavior, and evaluates whether their payload-free
> abstractions improve defenses against unseen live-adaptive attacks.

현재 `attack-memory-v1`의 220 episodes, 307 inferred transitions, 101 final slots는
schema와 annotation instrument를 개발하는 excluded legacy pilot이다. 이를 사후 보정해
본 데이터로 승격하지 않는다. AAMD-v1의 claim-bearing rows는 새 prospective run에서
explicit runtime receipt와 함께 다시 수집한다.

### 명칭 경계 — AAMD-v1은 ARMOR가 아니다

`ARMOR`는 이미 ICLR 2026 논문
[ARMOR: Aligning Secure and Safe Large Language Models via Meticulous Reasoning](https://proceedings.iclr.cc/paper_files/paper/2026/hash/59e828197370fad05ee2f975b5da6cd9-Abstract-Conference.html)의
고유 방법명이다. 기존 ARMOR는 외부의 갱신 가능한 공격 전략 library 분석, core intent
추출, policy 기반 안전성 검증으로 이어지는 3단계 reasoning defense다. 따라서 본
데이터셋과 protocol의 이름은 `AAMD`/`AAMD-v1`로만 사용한다. 기존 ARMOR는 AAMD의
payload-free abstraction을 입력받을 수 있는 **방어 baseline/reference consumer**일 뿐,
우리 데이터셋이나 새 방법의 이름이 아니다. 논문의 novelty도 ARMOR의 reasoning
pipeline이 아니라 memory lifecycle corpus, attack-side causal validity, defense-side
actionability의 결합에 둔다.

## 왜 데이터셋 논문으로 성립하는가

강한 데이터셋 논문은 크기만 큰 파일을 공개하지 않는다. 다음 네 가지를 함께 제공한다.

1. 기존 자료가 표현하지 못한 연구 단위와 그 단위를 일관되게 만드는 수집 protocol
2. annotation 및 provenance 품질을 재현 가능하게 검사하는 schema와 validator
3. 데이터가 의도한 연구 문제에 실제로 쓸모가 있음을 보이는 baseline과 downstream task
4. 명시적인 범위, 실패 사례, license, 안전한 접근과 유지 정책

안전 데이터셋 분야에도 같은 패턴이 있다. WildJailbreak는 공격성 prompt-response
자료를 안전 훈련에 사용해 robustness와 over-refusal, 일반 성능을 함께 평가했다.
WildGuardMix는 moderation dataset으로 학습한 guard를 여러 외부 benchmark와 실제
jailbreak 차단 설정에서 검증했다. BeaverTails는 안전 label과 helpfulness/harmlessness
preference를 분리하고 moderation 및 RLHF 응용을 보였다. 즉 “방어에 도움 되는
데이터”라는 주장은 row 수가 아니라 **독립된 downstream safety–utility 결과**로
성립한다.

AAMD-v1도 같은 기준을 따르되, 기존 prompt-response dataset이 거의 기록하지 않는
**적응형 공격의 메모리 lifecycle과 대화 진행의 연결지점**을 주 artifact로 삼는다.

## 선행연구 지도와 남아 있는 간극

아래 표는 2026-11-16까지 확인한 1차 논문·공식 project 자료를 기준으로 한다. 이것은
우선순위가 높은 근접 연구 목록이며, 논문 제출 직전에는 검색 cutoff와 포함·제외 로그를
갱신한다. 아직 `first` 주장은 하지 않는다.

| 연구 | 데이터/검증 기여 | AAMD-v1과의 핵심 차이 |
|---|---|---|
| [WildTeaming / WildJailbreak, NeurIPS 2024](https://proceedings.neurips.cc/paper_files/paper/2024/hash/54024fca0cef9911be36319e622cde38-Abstract-Conference.html) | 262K vanilla/adversarial prompt-response와 5.7K tactic cluster; 안전 훈련 후 공격 robustness·over-refusal·일반 능력 검증 | 주로 완성된 prompt-response와 tactic이며 target feedback에 따른 write–retrieve–use memory lineage가 없음 |
| [WildGuard, NeurIPS Datasets & Benchmarks 2024](https://proceedings.neurips.cc/paper_files/paper/2024/hash/0f69b4b96a46f284b726fbd70f74fb3b-Abstract-Datasets_and_Benchmarks_Track.html) | 92K moderation data, 5K human test, 10개 외부 benchmark와 interface-level jailbreak 감소로 utility 검증 | moderation label 자료이며 adaptive attacker memory와 다음 연산의 연결을 기록하지 않음 |
| [AEGIS2.0, NAACL 2025](https://aclanthology.org/2025.naacl-long.306/) | human annotation과 multi-LLM jury로 만든 34,248 human–LLM interaction, 12개 상위·9개 세부 위험 taxonomy; 경량 guard 학습과 새 위험 category 일반화로 downstream utility 검증 | 안전 분류용 정적 interaction 단위이며 response-conditioned adaptation이나 memory lifecycle/receipt가 없음 |
| [BeaverTails, NeurIPS Datasets & Benchmarks 2023](https://proceedings.neurips.cc/paper_files/paper/2023/hash/4dbb61cb68671edc4ca3712d70083b9f-Abstract.html) | 333,963 QA safety meta-label과 361,903 preference pair; moderation·RLHF 응용 | 단일 QA preference 중심이며 공격자의 상태·검색·memory lifecycle이 없음 |
| [Bot-Adversarial Dialogue, NAACL 2021](https://aclanthology.org/2021.naacl-main.235/) | human-and-model-in-the-loop adversarial 대화로 안전 모델을 학습하고 안전성과 engagingness를 함께 검증 | 사람의 adversarial dialogue 수집이며 persistent machine memory의 provenance를 대상으로 하지 않음 |
| [Learning from the Worst, ACL-IJCNLP 2021](https://aclanthology.org/2021.acl-long.132/) | 훈련된 annotator와 모델을 loop에 둔 4개 round에서 40K 항목과 15K perturbation을 수집하고, 후반 round 학습이 공격 내성과 외부 기능 test를 개선함을 검증 | 반복적 adversarial data→방어 개선의 강한 선례지만 hate classification 항목이며 LLM 공격 trajectory나 memory operation 단위가 아님 |
| [DiaSafety, Findings ACL 2022](https://aclanthology.org/2022.findings-acl.308/) | context-sensitive dialogue safety taxonomy, dataset, classifier baseline | context dependency는 다루지만 공격자가 target response를 소비해 memory를 갱신하는 과정이 없음 |
| [Gandalf the Red, ICML 2025](https://proceedings.mlr.press/v267/pfister25a.html) | crowd-sourced gamified platform에서 279K realistic adaptive prompt attack을 수집하고, D-SEC으로 multi-step security와 benign-user utility를 함께 분석 | live 적응성과 security–utility 평가의 가장 가까운 선례지만 재사용 가능한 write/read/update memory object와 item-level consumption lineage가 주 artifact는 아님 |
| [ICAG, EMNLP 2024](https://aclanthology.org/2024.emnlp-main.1121/) | attack·defense agent가 성공/실패 시도에서 insight를 추출해 공격 prompt와 방어 system prompt를 반복 갱신하고 unseen attack과 model transfer를 평가 | 공격–방어 prompt 공진화의 직접 선행 방법이지만, 여러 attack method의 item-level memory lifecycle·consumption receipt·human–LLM annotation을 통합한 검증 데이터셋은 아님 |
| [HarmBench, ICML 2024](https://proceedings.mlr.press/v235/mazeika24a.html) | 18 red-teaming method와 33 target/defense를 비교하는 표준 threat model·평가 framework | 표준화의 모델이지만 memory-event corpus나 방어용 transition annotation은 아님 |
| [JailbreakBench, NeurIPS Datasets & Benchmarks 2024](https://proceedings.neurips.cc/paper_files/paper/2024/hash/63092d79154adebd7305dfd498cbff70-Abstract-Datasets_and_Benchmarks_Track.html) | behavior, attack artifact repository, threat model, system prompt/chat template/scorer와 leaderboard | 주 artifact가 정적 behavior와 adversarial prompt이며 memory-mediated adaptation을 표현하지 않음 |
| [MUSE, EMNLP 2025](https://aclanthology.org/2025.emnlp-main.1080/) | MCTS의 성공 endpoint와 high-risk intermediate node로 preference data를 만들고 multi-turn defense 학습에 사용 | within-run search trajectory를 방어에 쓰지만 cross-episode memory write/retrieval lifecycle corpus는 아님 |
| [Adversarial Déjà Vu, ICLR 2026](https://proceedings.iclr.cc/paper_files/paper/2026/hash/ab41709d06e9303c25ad6742ae661198-Abstract-Conference.html) | 32 attack paper에서 skill을 추출해 sparse dictionary로 압축하고 temporal unseen attack에 대한 ASCoT robustness 검증 | attack primitive coverage가 중심이며 target response가 다음 memory operation을 바꾸는 runtime trace가 아님 |
| [SafetyMem, ACL 2026](https://aclanthology.org/2026.acl-long.1168/) | jailbreak pattern의 semantic memory와 탐지 실패에서 갱신되는 procedural episodic memory로 학습 없이 adaptive defense를 구성하고 효율·해석·robustness를 평가 | 방어 memory 방법의 가장 가까운 선행이므로 반드시 비교해야 하지만, 이질적 공격자의 write–retrieve–consume chain과 attack-side matched counterfactual을 공개 데이터 계약으로 검증하는 데이터셋 기여는 아님 |
| [ARMOR, ICLR 2026](https://proceedings.iclr.cc/paper_files/paper/2026/hash/59e828197370fad05ee2f975b5da6cd9-Abstract-Conference.html) | external strategy library 분석 → core intent 추출 → policy 검증의 3단계 reasoning으로 OOD jailbreak을 방어 | 전략 library를 소비하는 방어 method이며, attack memory의 lifecycle/provenance/negative evidence를 재사용 데이터셋으로 표준화한 것은 아님 |
| [Causal Analyst, NDSS 2026](https://www.ndss-symposium.org/ndss-paper/a-causal-perspective-for-enhancing-jailbreak-attack-and-defense/) | 7 LLM의 35K attack attempt를 37개 해석 가능한 feature로 주석하고 공격·guardrail 응용 검증 | template/prompt feature의 인과 구조가 중심이며 장기 memory의 write–retrieve–use가 없음 |
| [SafeMT, ACL 2026](https://aclanthology.org/2026.acl-long.1920/) | 10K multimodal multi-turn sample, 17 scenario, 4 jailbreak method와 dialogue safety moderator | multi-turn benchmark지만 적응형 memory의 runtime 사용 근거와 cross-episode 축적이 없음 |
| [ARMs project/paper](https://arms-redteaming-agent.github.io/) | layered memory로 생성한 30K multimodal red-team instance를 보고하고 safety fine-tuning utility를 평가 | dataset은 성공·선별된 final instance 중심이며 공개 memory write/read/consumption/negative lifecycle corpus가 아님 |
| [MemoAttack, 2026 preprint](https://arxiv.org/abs/2605.29237) | skill-structured memory, promotion/retirement/eviction, posterior selection과 attack-side memory ablation을 분석 | 가장 가까운 연구지만 defense-side experiment를 명시적으로 future work로 남기며 민감 memory artifact의 공개 dataset을 기여로 삼지 않음 |

데이터셋 검증 관점에서 AEGIS2.0은 taxonomy가 guard 학습과 새 category 일반화에
실제로 쓰이는지, Learning from the Worst는 successive adversarial round가 더 견고한
모델을 만드는지, Gandalf the Red는 실제 적응적 사용자와 정상 사용자의
security–utility trade-off를 함께 측정해야 함을 보여준다. AAMD-v1은 이 세 선례를
결합해 **주석 신뢰도**, **공격 측 memory의 인과적 유효성**, **unseen live-adaptive
공격에서의 방어 효과와 정상 utility**를 서로 다른 gate로 검증한다. 다만 세 연구 모두
item-level write–retrieve–consume–revise lineage를 방어 재사용 단위로 공개하지 않으므로,
그 빈칸이 AAMD-v1의 구체적 데이터 기여다.

### 선행연구 검색을 재현 가능하게 남긴다

최초성 주장을 ad-hoc 검색에 의존하지 않는다. G0와 논문 제출 직전에
ACL Anthology, ICLR, NeurIPS, PMLR, NDSS의 공식 proceedings와 arXiv를
독립적으로 재검색한다. 검색어는 `jailbreak/adaptive attack/red teaming` ×
`memory/trajectory/dataset/benchmark` × `defense/system prompt/guardrail`의 조합으로
고정하고, 각 후보에 다음을 남긴다.

- 검색 DB, query, 시각, 버전과 inclusion/exclusion 이유
- primary paper/project/data/code URL과 access date, commit/revision, license
- data unit, adaptive feedback, memory lifecycle, negative evidence, annotation, split
- attack-side causal validation, downstream defense task, utility/over-refusal, live re-attack
- 코드·데이터 실제 공개 상태와 재현 성공/실패

이 log와 machine-readable comparison matrix를 supplementary artifact로 공개한 뒤에만
`to our knowledge`를 사용한다. 후보를 찾았지만 코드가 없다는 이유로 비교표에서
제거하지 않는다.

가장 중요한 비교는 MemoAttack과 ARMs-Bench다. 두 연구는 공격 memory가 실재하고
효과가 있음을 강하게 보여주므로, AAMD-v1은 “공격이 memory를 쓴다”를 novelty로
주장할 수 없다. 대신 다음 미충족 조합을 기여 후보로 삼는다.
방어 측에서는 ICAG, SafetyMem, ARMOR가 직접 선행연구다. 따라서 “공격
경험을 요약해 system prompt/방어 memory에 넣는다” 또는 “공격자와 방어자를
반복 대결시킨다”도 단독 novelty가 아니다. AAMD-v1은 어떤 방어 algorithm이
이겼다는 방법 논문 대신, 이러한 방법들이 공통으로 검사할 수 있는
감사 가능한 memory data unit과 validation benchmark를 기여한다.

- 여러 이질적인 attack method를 하나의 event contract로 정규화
- 성공 winner뿐 아니라 write/reject/merge/quarantine/retrieve/failure를 모두 보존
- exact item이 실제 attacker context에 들어간 consumption receipt 공개
- memory 효과에 대한 matched attack-side counterfactual
- payload-free attack-dynamics annotation과 human–LLM 판단 lineage
- unseen live-adaptive 공격에서의 defense actionability 검증

이 여섯 조건의 조합이 선행연구에 없는지는 submission 직전 systematic search로 다시
확인한다. 논문에서는 “the first” 대신 우선 “to our knowledge, the first dataset to jointly
provide ...” 형태도 모든 포함 기준과 공개 artifact가 완성된 뒤에만 사용한다.

## 연구 기여

### C1 — Provenance-complete adaptive attack-memory corpus

다섯 heterogeneous adaptive method와 세 target scale에 대해 동일한 event contract로
episode, transition, memory candidate, read, update, terminal outcome을 수집한다. 성공,
실패, timeout, fallback, no-memory, reject, replace, quarantine을 삭제하지 않는다.

### C2 — Co-adjudicated attack-dynamics taxonomy

사람의 blind initial label, 고정 LLM proposal, 사람의 final label, 독립 adjudication을
모두 보존한다. 공격 내용 category와 response-signal–adaptation-operator taxonomy를
분리하고 suggestion-induced anchoring을 측정한다. 상세 절차는
[`HUMAN_LLM_ATTACK_DYNAMICS_DATA_PROTOCOL_V1.md`](HUMAN_LLM_ATTACK_DYNAMICS_DATA_PROTOCOL_V1.md)를
따른다.

### C3 — Attack-side memory validity benchmark

기록된 object가 단순 trace가 아니라 공격 memory임을 exposure receipt와 matched
counterfactual로 검증한다. intact, linkage-shuffled, unrelated same-token, empty memory를
같은 initial state와 budget에서 live rollout한다.

### C4 — Defense actionability benchmark

데이터의 추상화가 저토큰 system-prompt defense를 만드는 데 실제로 유용한지 확인한다.
held-out method가 방어 응답을 본 뒤 다시 적응하는 live setting에서 safety, utility,
over-refusal, token/cost를 함께 측정한다. ARMOR는 데이터 소비를 검증하는 reference
consumer 중 하나이며 데이터셋 자체와 동일시하지 않는다.

## 연구 질문

### RQ-D1 — Construct validity and coverage

사전등록된 universe에서 명시적 target-response consumption, memory write/read/update,
terminal outcome이 완전한 corpus를 outcome cherry-picking 없이 구축할 수 있는가?

주 endpoint:

- registered-cell completion rate
- explicit response-dependency receipt rate
- retrieval selection/consumption receipt rate
- memory-head before/after reconciliation
- exactly-one terminal outcome rate
- missing, unknown, censored 및 infrastructure-failure denominator

### RQ-D2 — Attack-side memory utility

Intact memory가 동일 형식·길이의 linkage-shuffled 또는 unrelated memory보다 새로운
live-adaptive rollout의 success probability와 search efficiency를 높이는가?

이 질문은 memory object의 construct validity를 보강하지만, 공격 성공 자체를 최종
사회적 가치로 주장하지 않는다. 방어용 corpus의 원인이 되는 memory가 실제로 작동했는지
확인하는 manipulation check다.

### RQ-D3 — Annotation reliability and bias

Blind-first human–LLM co-adjudication이 human-only와 LLM-only보다 transition taxonomy의
신뢰도 또는 비용을 개선하면서 suggestion-induced label shift를 측정·통제하는가?

### RQ-D4 — Defense actionability

동일 compiler와 prompt-token budget에서 intact co-adjudicated memory가 generic,
success-only, raw-summary, frequency-only, linkage-broken 조건보다 sealed live-adaptive
ASR을 낮추면서 benign utility non-inferiority를 만족하는가?

### RQ-D5 — Transfer and efficiency

위 효과가 taxonomy 단계부터 격리된 unseen attack method, target scale, behavior domain과
data/prompt budget에 걸쳐 유지되는가?

Qwen2.5-VL 3B/7B/32B만 평가하면 `cross-scale transfer within one model family`라고
부른다. `cross-model-family transfer`를 주장하려면 최소 한 개의 비-Qwen target을 sealed
protocol에 추가해야 한다.

## Attack trace와 attack memory의 구분

대화 A 뒤에 대화 B가 이어졌다는 사실만으로 memory dataset이 되지 않는다. AAMD-v1에서
memory라는 명칭을 쓰려면 다음 chain이 runtime event로 연결돼야 한다.

```text
experience event
  -> memory candidate write
  -> retain / merge / reject / quarantine
  -> later retrieval selection
  -> exact item inserted into attacker-visible context
  -> next adaptation operation
  -> target response and terminal or progress outcome
```

LLM 내부에서 memory를 실제로 “생각했다”는 것을 직접 관찰할 수는 없다. 따라서 두
증거를 혼동하지 않는다.

- `exposure evidence`: exact memory hash와 rendering hash가 attacker input에 들어간 receipt
- `causal evidence`: matched intact/shuffled/unrelated/empty rollout의 반복 효과

Retrieval label만 있거나 program order에서 edge를 추론한 legacy row는
`inferred_trace`이며 AAMD-v1 adaptive core에 포함하지 않는다.

## Memory evidence ladder

| Level | 명칭 | 필요한 근거 | 허용되는 주장 |
|---|---|---|---|
| M0 | observed trace | episode·turn 순서만 존재 | 대화 흔적 |
| M1 | response-attested transition | consumed target-response event/hash와 next operator | response-conditioned adaptation |
| M2 | write-attested candidate | source transition과 write decision receipt | memory candidate 생성 |
| M3 | lifecycle-attested memory | retain/merge/reject/quarantine와 head before/after | memory store 변화 |
| M4 | retrieval-consumed memory | exact item·rank·score·render hash·attacker-input receipt | later memory exposure |
| M5 | attack-effect-tested memory | matched counterfactual effect와 CI | attack-side utility가 검정됨 |
| M6 | defense-effect-tested abstraction | held-out defense effect, utility, tokens와 CI | defense actionability가 검정됨 |

한 row가 M6라고 해서 항상 효과가 positive라는 뜻은 아니다. 각 검증 축을 별도 필드로
보존한다.

- `trace_verified`
- `retrieval_attested`
- `attack_effect_tested`와 effect estimate/CI
- `defense_effect_tested`와 safety/utility/token estimate/CI
- `validation_direction`: positive, null, negative, inconclusive

무효하거나 역효과가 난 memory도 삭제하지 않는다. 실패 memory가 있어야 survivor bias를
막고 어떤 추상화가 방어에 위험한지 연구할 수 있다.

## 논리적 record family

| Record family | 필수 내용 |
|---|---|
| `episode` | method/revision, native 또는 augmented state, target/attacker/judge exact revision, behavior cluster, seed, budget, terminal status, cost |
| `turn` | modality, private input/response hash, runtime receipt, visibility policy, sequence/branch |
| `adaptation_transition` | predecessor state, consumed response event, observed response signal, next adaptation operator, parent edge |
| `memory_candidate` | source transition, abstraction, proposed scope, evidence strength, candidate hash |
| `memory_write_decision` | retain/merge/replace/reject/quarantine, reason, head before/after hash |
| `memory_retrieval` | retrieval query hash, ranked item hashes/scores, selected item와 memory snapshot receipt |
| `memory_use_receipt` | exact item hash, attacker-input/render hash, insertion position, next operation과 runtime identity |
| `annotation_event` | 각 단계 event hash를 포함한 immutable chain snapshot: human initial, LLM proposal, human final, independent votes, adjudication, codebook hash |
| `attack_counterfactual_trial` | intact/shuffled/unrelated/empty arm, paired block, effect estimate and uncertainty |
| `defense_affordance` | candidate invariant, benign exception, predicted adaptation; intervention hypothesis임을 명시 |
| `defense_validation_trial` | consumer/compiler, prompt hash/tokens, held-out fold, live outcome, utility/over-refusal/cost |
| `artifact_manifest` | schema/code/source/model/taxonomy hash, counts, exclusions, missingness, release tier |

관측 사실, annotator 판단, intervention hypothesis, 실험 결과를 다른 namespace와 file로
둔다. `defense_invariant`를 gold observation처럼 저장하지 않는다.

## Native state와 harmonized external memory

PAIR, TAP, Crescendo 등은 target feedback과 within-episode search state를 쓰지만 upstream
방법이 모두 persistent cross-episode memory를 정의하는 것은 아니다. 다음을 분리한다.

- `native_adaptive_state`: upstream method가 원래 유지하는 대화·tree·population·library
- `harmonized_external_memory`: 이 연구가 동일 contract로 추가한 cross-episode memory
- `no_memory_control`: `empty` 인과 대조군에만 쓰는 예약값. 저장·검색·노출된 memory가
  없으므로 stored-memory claim의 분모나 M3 이상 승격에 쓰지 않는다.

외부 memory를 붙인 PAIR를 “PAIR의 원래 memory”라고 쓰지 않는다. `memory-augmented
PAIR adapter`라고 표시하고 native parity arm을 별도로 유지한다. Adapter report에는
무엇이 upstream semantics이고 무엇이 augmentation인지 field-by-field로 남긴다.

## 수집 protocol

### 사전 고정

- attack method, exact upstream revision, adapter mapping
- behavior source revision, license, semantic cluster와 split salt commitment
- target/attacker/judge model exact revision 및 chat template
- feedback visibility: primary는 target response only
- seed, target-call/token/time budget, stopping/retry rule
- memory capacity, retrieval policy와 rendering template
- event schema, canonical JSON, hash-chain과 terminal outcomes
- collection matrix와 power cap

### Outcome-independent collection

Method × target × behavior category × seed × feedback arm의 registered cell을 결과 전에
고정한다. Episode와 파생 turn/transition/memory event는 같은 split에 둔다. 성공한 cell을
추가 수집할 수는 있지만 enriched diagnostic으로 표시하고 primary 분포와 섞지 않는다.

다음 사건은 모두 terminal 또는 lifecycle denominator에 남긴다.

- strict success, ordinary failure, safe completion/refusal
- invalid attacker output, target/attacker/judge timeout
- budget exhaustion, policy filter block, infrastructure error
- cancelled-before-call, no-trajectory, no-memory fallback
- candidate retain/merge/replace/reject/quarantine/evict

### Explicit receipt

각 target response는 event ID와 content hash를 가진다. 다음 attacker generation 전에
renderer가 실제로 사용한 response event IDs와 memory item hashes, 정렬 순서,
rendered-context hash를 기록한다. 단순히 retrieval 함수를 호출했다는 log만으로 consumed
receipt를 대신하지 않는다.

## Attack-side causal validation

같은 behavior cluster, target checkpoint, initial conversation state, attacker seed와 call/token
budget으로 다음 네 arm을 paired block으로 실행한다.

1. `intact`: 정상 linkage와 semantic retrieval
2. `linkage_shuffled`: format/token은 유지하고 transition parent를 block 안에서 섞음
3. `unrelated_same_token`: 다른 cluster memory로 길이·schema·token을 맞춤
4. `empty`: memory 없음; compute 차이를 함께 보고하는 diagnostic

주 비교는 intact vs linkage-shuffled다. 모든 arm에서 attacker는 새 target response를 보고
다시 적응한다. Frozen replay는 integrity/debugging에는 쓸 수 있지만 primary adaptive
claim에는 사용하지 않는다.

효과의 단위는 `item`, `bundle`, `compiler`로 분리한다. Bundle intervention 결과를 개별
item의 M5/M6로 승격하지 않는다. Item-level 주장은 leave-one-item-out 또는 item-scoped
intervention이 있어야 하며, arm별 memory snapshot/write state를 격리하고 paired block
안의 실행 순서를 무작위화한다. Linkage shuffle은 token 수만 맞추지 않고 linkage가 실제로
깨졌고 다른 coherence는 유지됐는지 manipulation check를 통과해야 한다.

주 지표:

- paired strict episode ASR risk difference
- budgeted cumulative ASR
- target calls/expansion attempts to success
- progress-event rate와 memory reuse yield
- negative-transfer rate
- method/target/behavior별 effect heterogeneity

Episode 또는 behavior cluster를 독립 resampling unit으로 사용한다. Turn을 독립 관측치로
부풀리지 않는다.

## Annotation quality component

상세 절차는 별도 human–LLM protocol을 따른다. Dataset umbrella가 강제하는 최소 조건은
다음과 같다.

- 사람은 LLM proposal과 downstream outcome을 보기 전에 initial label을 잠금
- 고정 LLM model revision, prompt hash, decoding, seed와 codebook hash 기록
- initial→final shift, accept/edit/reject/retain/abstain 보존
- anchoring의 인과 효과는 `human-only delayed reconsideration`, `LLM-only`,
  `human→versioned LLM proposal`을 annotator×task block에서 사전 무작위 배정해 비교
- proposal correctness/confidence 조작과 독립 expert reference를 사전등록하여 단순 재고 효과와
  제안 영향 분리
- 핵심 memory-validity field는 전수 또는 사전등록된 고비율 이중 주석
- 희귀 label, unmapped, low-confidence, human–LLM disagreement는 독립 adjudication
- method, target, success, judge score, memory retention 결과는 1차 dynamics 판정에서 숨김
- agreement 미달 field는 hard gold가 아니라 label distribution/uncertainty로 공개

지표는 human–human Krippendorff alpha, multilabel Jaccard/F1, confusion matrix,
human–LLM agreement, anchoring shift, abstain/unmapped, 시간과 비용을 포함한다.

## Split, fold와 leakage control

통계 보고 단위는 semantic behavior cluster지만 split 배정 단위는 더 큰
`connected_lineage_component`다. Base behavior, source-row commitment, paraphrase cluster,
attack template family, trajectory parent, memory-derivation parent, augmented adapter revision,
compiler-example lineage를 graph edge로 묶고 connected component 전체를 한 split에 둔다.
Exact match, embedding near-duplicate, blinded LLM-assisted review를 모두 통과해야 한다.

1. `excluded-pilot`: legacy pack과 새 instrumentation pilot; taxonomy/UI/교육 전용
2. `build-induction`: fold-specific open code 발견 허용
3. `build-application`: 동결 taxonomy 적용과 reliability 검증
4. `selection`: consumer, token budget와 diagnostic ablation 선택
5. `confirmation`: 한 번의 sealed defense evaluation

Semantic behavior cluster와 episode 단위로 split한다. 같은 base behavior/paraphrase/episode가
여러 split에 나타나면 안 된다.

Leave-one-method-out fold에서는 held-out method가 다음 과정 모두에서 0건이어야 한다.

- taxonomy leaf discovery와 definition/example 작성
- annotator calibration
- memory abstraction과 defense affordance 작성
- compiler/reference consumer 개발
- prompt/token/threshold 선택
- 오류 분석과 수정

Universal top-level axes는 문헌과 excluded pilot에서 G0 전에 동결할 수 있다. Data-derived
subcode는 네 training method에서만 만들고 held-out의 새 유형은 `unmapped`로 기록한다.

가능하면 데이터셋 v1 동결 뒤 발표된 새 attack method를 temporal confirmation으로
추가한다. 이 결과는 LOMO와 별도 표로 보고한다.

## Defense actionability benchmark

데이터셋이 방어에 “도움 된다”는 것은 특정 compiler가 높은 점수를 냈다는 뜻이 아니다.
데이터 효과와 algorithm 효과를 분리하기 위해 최소 두 독립 consumer에서 방향을
확인한다.

- deterministic template/rule compiler
- frozen LLM compiler
- 선택적으로 blind human prompt designer

또한 가장 가까운 기존 방어 방법인 ICAG, SafetyMem, ICLR 2026 ARMOR를
mandatory prior-method baseline registry에 놓는다. 코드·license·model access 문제로 재현할 수
없다면 조용히 제외하지 않고 exact revision, access date, 실패 단계와 제외 이유를
보고한다. 이들은 방어 mechanism이 다르므로 system-prompt token을 인위적으로
같게 맞추지 않고, 각 방법의 원래 resource contract과 실제 호출·token·latency를
함께 보고한다. AAMD 내부 ablation만 exact prompt-token matching을 적용한다.

비교 조건:

1. native target without added defense
2. token-matched generic safety system prompt
3. final-success-only memory summary
4. raw transcript summary
5. success-only memory
6. frequency-only category summary
7. linkage-broken transition memory
8. unrelated/random same-token memory
9. single-method memory
10. human-only annotation
11. LLM-only annotation
12. human-first co-adjudicated intact memory

64/128/256 token 같은 정확한 budget grid는 G5 전에 tokenizer별로 고정한다. 모든 비교는
같은 target tokenizer의 실제 system-prompt token 수를 맞춘다.

Primary endpoint는 cluster-macro strict episode ASR이다. 동시에 다음 조건을 만족해야
positive defense validation으로 판정한다.

- preregistered benign utility non-inferiority
- gross over-refusal ceiling
- explanation leakage arm의 재적응 비용 보고
- prompt tokens, latency, target/attacker/judge calls와 비용 보고
- method/target/behavior별 uncertainty

특정 consumer 하나에서만 이득이 나면 dataset actionability가 아니라 consumer-method
interaction으로 보고한다.

## 재사용 가능한 benchmark tasks

사람 작업공간의 단계, 공개 데모와 claim-bearing 수집의 경계, 제출 manifest와
track별 사용법은
[`AAMD_BENCHMARK_AND_HUMAN_WORKSPACE_V1.md`](AAMD_BENCHMARK_AND_HUMAN_WORKSPACE_V1.md)에,
fail-closed machine contract는
[`aamd_benchmark_v1.json`](../configs/aamd_benchmark_v1.json)에 고정한다.

| Task | 입력/출력 | 지표 | 공개 tier |
|---|---|---|---|
| T1 Memory Trace Verification | event subgraph → evidence level/오류 | macro F1, calibration | public payload-free |
| T2a Retrieval Imitation / T2b Effective Retrieval | sanitized state → observed vs causally effective memory IDs | Recall@K, MRR, nDCG, downstream effect | public/controlled |
| T3 Adaptation Prediction | response signal/history → next operator | macro F1, hierarchical distance | public payload-free |
| T4 Defense Affordance Generation | memory subgraph → invariant+benign exception | human rubric, compression, faithfulness | controlled |
| T5 Live-Adaptive Defense | frozen prompt/consumer → live rollout | ASR, utility, over-refusal, cost | controlled evaluation server |

T1–T3은 데이터셋 논문이 특정 방어 compiler와 독립적으로 재사용될 수 있게 한다. T4–T5는
dual-use 위험 때문에 접근 통제된 raw layer 또는 evaluation server를 사용한다.
각 task는 전체 record가 아니라 사전등록된 field-level projection만 공개한다. Retrieval
rank/item, 다음 operation, human defense label, sealed validation outcome처럼 target 또는
proxy가 되는 field는 입력에서 제거하고, projection hash와 mask version을 split manifest에
기록한다.

## 통계와 quality gates

다음은 결과와 무관하게 0 또는 100%여야 하는 integrity gate다.

- claim-bearing provenance completeness: 100%
- registered episode의 exactly-one terminal outcome: 100%
- required field 누락: 0; 모르는 값은 명시적 `unknown`
- exact/semantic cluster split overlap: 0
- hash-chain과 manifest hash 오류: 0
- held-out taxonomy-source row: 0
- confirmation 이후 taxonomy/compiler 수정: 0
- public raw harmful payload/response/judge rationale/private path leakage: 0

Agreement threshold, minimum cell count와 utility non-inferiority margin은 excluded pilot과
simulation power analysis를 사용해 G0/G2 전에 고정한다. 편리한 결과를 본 뒤 threshold를
낮추지 않는다.

Primary paired comparisons는 behavior cluster block을 유지하고 cluster bootstrap 95% CI
또는 preregistered hierarchical/mixed-effects model을 사용한다. Attack method, target,
behavior category의 역할과 primary contrast order를 고정하고 secondary comparison에는
Holm 또는 FDR 보정을 적용한다. Utility는 “유의한 하락이 없었다”가 아니라 명시적인
non-inferiority test를 사용한다.

## Release tiers와 안전

민감 원문의 공개 SHA-256은 사용하지 않는다. 알려진 benchmark row 후보에 대한 dictionary
attack으로 source가 복원될 수 있기 때문이다. 공개 tier에는 domain-separated keyed
commitment와 redacted projection hash만 두고, 원문 mapping과 key는 sealed layer에 둔다.
Release별 Merkle root는 sealed mapping과 분리해 공개한다.

### Public

- payload-free episode/transition/memory lifecycle graph
- taxonomy, annotation uncertainty, validation status와 aggregate effect
- schemas, validators, codebooks, baseline code와 content hashes
- source/model/license manifest와 datasheet

### Controlled

- 연구자 심사 후 제공하는 최소 redacted bounded dialogue
- finer-grained response signal, retrieval evidence와 paired block metadata
- T2/T4 연구에 필요한 제한적 context

### Sealed

- raw harmful behavior/prompt/target completion
- judge rationale, source row ID, private split salts
- confirmation cases와 재현 가능한 공격 운영 artifact

공개 artifact만으로 operational jailbreak를 그대로 재생성할 수 없어야 한다. 동시에
public hash receipt와 aggregate count가 controlled/private layer의 존재와 변조 여부를
검증할 수 있어야 한다.

Annotator에게 위해 콘텐츠 노출 가능성을 고지하고 opt-out, 휴식, 최소 노출 UI, 보상과
지원 절차를 제공한다. Intended use는 authorized defense, audit, attack-dynamics research다.
Prohibited use는 무단 공격 자동화, 실제 사용자/서비스 대상 시험, access-control 우회다.

## Dataset card와 versioning

Datasheet에는 최소 다음을 기록한다.

- 동기, 구성, collection population과 sampling frame
- 각 source revision, license/terms와 포함·제외 사유
- 모든 method/adapter의 native 대 augmented state
- model/checkpoint/chat template/decoding/seed
- annotation UI, 인력, 교육, 보상, agreement와 anchoring
- 실패·누락·제외 denominator와 known biases
- Qwen family, 영어, method/behavior coverage 한계
- public projection에서 제거되어 생기는 정보 손실
- 계산·환경 비용
- intended/prohibited use, access, removal, update, deprecation policy
- version별 schema/taxonomy diff와 backward-compatibility

Version 의미:

- `0.x`: excluded pilot 및 schema 개발; efficacy claim 금지
- `1.0-rc`: prospective corpus 수집·annotation 완료, confirmation 미개봉
- `1.0`: sealed validation과 release manifest 완료
- taxonomy 의미 또는 split이 바뀌면 `2.0`; 과거 결과에 소급 적용 금지

## G0–G6에 통합되는 release lifecycle

| Gate | AAMD-v1 통과 근거 |
|---|---|
| G0 | dataset/annotation config·schema·event contract, source/model/prompt/seeds/metrics/stopping rules hash freeze |
| G1 | 다섯 adapter가 native parity와 동일 response/memory consumption receipt contract 통과 |
| G2 | behavior cluster/split, collection matrix, annotation queue, reviewer allocation와 power cap freeze |
| G3 | 새 excluded pilot에서 ledger, redaction, hash chain, blind-first UI, validator와 cleanup 검증 |
| G4 | build prospective corpus, fold-specific taxonomy induction/application, adjudication, memory causal validation 완료 |
| G5 | dataset release candidate hash와 reference consumers/token budgets/primary analysis freeze; corpus 수정 금지 |
| G6 | sealed LOMO live defense evaluation, 결과와 무관한 final manifest·datasheet·validation reports release |

`defense_validation_status`는 G6 이전에 `not_run`이어야 한다. G6 이후에만 `positive`,
`negative`, `null`, `inconclusive` 중 하나로 변경한다. Confirmation이 불리하더라도
재튜닝하지 않고 그대로 공개한다.

## 현재 구현과 주장 경계

현재 완료된 것은 다음이다.

- heterogeneous adaptive attack preregistration candidate
- behavior registry candidate와 split contract
- legacy payload-free memory audit pack과 explorer
- human–LLM attack-dynamics annotation protocol
- 본 AAMD-v1 umbrella protocol의 설계

아직 완료되지 않은 것은 다음이다.

- G0 upstream/model/license/runtime freeze
- 다섯 adapter의 G1 parity와 explicit consumption receipts
- prospective AAMD-v1 corpus 수집
- attack-side matched memory validation
- claim-bearing human–LLM annotation
- sealed defense actionability 결과

따라서 현재 허용되는 표현은 “we define and preregister AAMD-v1”이다. “we release a
defense-validated dataset” 또는 “our data improves defense”는 아직 허용되지 않는다.

## Venue와 modality 경계

현재 공격이 text channel만 사용하고 Qwen-VL을 단지 text target으로 호출한다면,
NeurIPS Datasets & Benchmarks, ACL/EMNLP의 safety/data framing이 더 자연스럽다. CVPR급
multimodal dataset contribution을 주장하려면 데이터 단위와 실험에 다음이 실제로
포함돼야 한다.

- image-conditioned response signal과 image/text cross-reference
- visual obfuscation, OCR/typography, grounding 및 modality-conflict adaptation
- 원 이미지와 파생 artifact의 content hash/transform provenance
- multimodal retrieval과 memory rendering receipt
- benign VQA/OCR/grounding utility
- 적어도 둘 이상의 VLM family 또는 claim을 Qwen cross-scale로 제한

단순히 VLM checkpoint를 사용했다는 이유로 multimodal contribution을 주장하지 않는다.

## Reviewer go/no-go

강한 데이터셋 논문으로 인정받을 조건:

- write–retrieve–consume–update lineage가 runtime receipt로 존재
- 성공뿐 아니라 전체 lifecycle과 negative evidence가 보존됨
- 여러 attack family가 동일 schema와 budget contract를 사용
- matched counterfactual로 memory construct validity를 확인
- annotation reliability와 LLM anchoring을 측정
- taxonomy부터 격리된 unseen live attack에서 defense utility를 검증
- safety뿐 아니라 benign utility, over-refusal와 token/cost를 통제
- 최소 두 독립 consumer에서 데이터 효과의 방향이 재현됨
- tiered release, datasheet, license와 deterministic verifier가 존재

핵심 주장이 기각되는 조건:

- post-hoc dialogue summary 또는 program-order edge를 memory라고 부름
- winner/final slot과 성공 trajectory만 공개
- retrieval label은 있으나 exact item/consumption receipt가 없음
- taxonomy 또는 compiler가 held-out method를 미리 봄
- frozen replay만으로 adaptive defense를 평가
- 같은 LLM이 생성·annotation·compiler·judge를 모두 담당하고 independent audit가 없음
- Qwen 세 크기만으로 model-family generalization을 주장
- 특정 compiler 하나의 결과를 데이터 효과로 해석
- confirmation을 보고 category, corpus 또는 prompt를 수정
- operational harmful payload를 제한 없이 공개

## 최종 논문 framing

이 데이터셋의 가치는 “공격을 더 잘하는 prompt를 많이 모았다”가 아니다. 공격자가
과거 경험과 target 반응을 어떻게 다음 행동으로 변환했는지를 감사 가능한 데이터로
만들고, 그 구조가 실제 공격의 원인이었는지와 방어 지식으로 뒤집어 쓸 수 있는지를
각각 반증 가능한 실험으로 검증하는 데 있다.

현재 preregistration 단계의 가장 안전한 제목 후보는 다음이다.

> **AAMD: A Defense-Evaluation-Ready Dataset of Memory-Mediated Adaptive Attacks on
> Language Models**

G6 evaluation을 완료하면 `Defense-Evaluated`, confirmation이 positive일 때만
`Defense-Validated`로 바꾼다. 프로젝트 내부의 학습형 prompt compiler와 동적
prompt optimization은 AAMD의 reference consumer 또는 별도 후속 method paper로
분리한다. `ARMOR`라는 이름은 기존 ICLR 2026 방어법을 가리킬 때만
사용한다.
