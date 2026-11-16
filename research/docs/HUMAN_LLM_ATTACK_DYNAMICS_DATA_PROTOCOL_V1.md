# Human–LLM Co-Adjudicated Attack-Dynamics Data Protocol v1

## 문서의 결론

사람과 LLM이 함께 적응형 공격 메모리를 카테고리화해 데이터셋을 만드는 것은
연구적으로 가능하다. 오히려 이 프로젝트에서는 사람이 모든 대화 전이를 수작업으로
정리하거나 LLM이 단독으로 라벨을 생성하는 것보다, **사람의 독립 판단과 LLM의
일관된 후보 제안을 모두 보존한 co-adjudication**이 더 적절하다.

다만 다음 두 주장은 구분해야 한다.

- 허용 가능한 주장: “사전등록된 표본에서 사람의 blind-first 판단, 고정된 LLM 제안,
  사람의 사후 수정, 독립 조정을 모두 기록해 적응형 공격의 대화 동학 taxonomy를
  구축했고, 그 taxonomy가 unseen 공격 방법의 저토큰 방어에 기여하는지 검증했다.”
- 허용할 수 없는 주장: “LLM이 먼저 분류하고 사람이 확인했으므로 객관적이고
  보편적인 최적 taxonomy를 만들었다.”

따라서 데이터 생성 방식 자체는 출판 가능한 방법이지만, 논문의 핵심 novelty는 단순한
human–LLM annotation이 아니다. 핵심은 다음 네 요소가 하나의 검증 가능한 흐름을
이룬다는 데 있다.

1. 단일 공격 문구가 아니라 **대화 이력에 반응해 다음 연산이 바뀐 transition**을
   주석 단위로 삼는다.
2. LLM suggestion이 사람 판정을 바꾸는 anchoring 효과까지 직접 측정한다.
3. 주석된 transition을 짧고 설명 가능한 defense invariant로 컴파일한다.
4. taxonomy를 만들 때 보지 않은 공격 방법과 타깃 모델에서 live-adaptive 방어 효과와
   정상 성능을 함께 검증한다.

이 조건을 만족하면 리뷰어가 보기에 이것은 “LLM으로 라벨을 값싸게 만든 데이터”가
아니라, **적응형 공격의 장기 대화 구조를 방어 가능한 지식으로 바꾸는 데이터 구축 및
검증 방법론**이 된다.

## 현재 프로젝트 자료에 대한 판정

현재 공개 `attack-memory-v1`은 다음 관측치를 제공한다.

- 220개 episode와 520개 target query
- 307개 순서 기반 strategy transition
- 213개 trajectory candidate와 7개 no-trajectory episode
- max-per-slot 선택 뒤 남은 101개 final slot

이 자료는 taxonomy 초안, annotation UI, 정상 예외, 반증 과제를 설계하는 **legacy
exploratory pilot**으로는 유용하다. 그러나 다음 이유로 아직 claim-bearing annotation
corpus는 아니다.

1. transition 일부가 runtime receipt가 아니라 프로그램 순서에서 추론됐다.
2. final slot은 선택 뒤 남은 survivor-biased view이다.
3. 현재 사이트 기록은 사람이 자유롭게 항목을 고르고 localStorage에 자유 텍스트를
   저장하므로 고정 표본 할당과 미완료 denominator가 없다.
4. 사람의 LLM 열람 전 판정, LLM model/prompt/seed, 사후 수정, 독립 조정 이력이 없다.
5. legacy 3B 실행 결과만으로 여러 공격 방법과 타깃 모델의 일반화를 주장할 수 없다.
6. public payload-free projection만으로는 세밀한 대화 연결 의미를 모두 판정하기
   어렵다.

그러므로 기존 pack을 폐기하지 않는다. 대신 다음 용도로 명확히 제한한다.

- codebook 초안과 annotation instrument 개발
- 파일럿 annotator 교육 및 경계 사례 발굴
- 공개 demo와 연구자가 검토할 작업 후보 제공
- 본 실험과 분리된 excluded pilot

논문용 데이터는 사전등록된 heterogeneous attack run의 append-only event ledger에서
새로 생성한다. 기존 pack에서 고안한 모든 category는 본 실험 전 `candidate`로
표시하며, 본 데이터의 효능 결과로 소급 정당화하지 않는다.

## 선행연구에 근거한 연구적 타당성

LLM을 annotation 보조자로 쓰는 것 자체에는 충분한 긍정 근거가 있다. Gilardi et
al.은 여러 텍스트 분류 과제에서 ChatGPT annotation이 crowd worker보다 높은 품질과
낮은 비용을 보일 수 있음을 보고했다. CoAnnotating은 사람과 LLM의 상보성을 이용해
검토 대상을 배분하는 협업 절차를 제시했고, MEGAnno+는 model configuration, prompt,
job, verification을 함께 추적하는 annotation provenance의 필요성을 보여준다.

하지만 이 근거는 LLM label을 곧바로 ground truth로 인정한다는 뜻이 아니다. 대규모
사전등록 실험인 Schroeder et al.은 LLM suggestion을 본 사람의 label distribution이
제안 방향으로 움직일 수 있고, 그 label로 같은 LLM을 평가하면 성능이 인위적으로
상승할 수 있음을 보였다. PNAS Nexus의 비교 연구도 annotation 신뢰도가 task, model,
prompt에 따라 크게 변함을 보고한다. 따라서 LLM은 **고정되고 감사 가능한 제안자**로
두고, 최종 데이터는 사람의 독립 판단과 조정 절차를 거쳐야 한다.

품질 보고에는 단순 percent agreement만 쓰지 않는다. Artstein and Poesio가 정리한
것처럼 label scale, 다중 annotator, 결측과 다중라벨 구조에 맞는 agreement 계수를
선택해야 한다. 데이터의 동기, 구성, 수집·주석 과정, 사용 한계와 유지 정책은
Datasheets for Datasets 형식으로 함께 공개한다.

주요 방법론 근거는 다음과 같다.

- [Gilardi et al., PNAS 2023](https://doi.org/10.1073/pnas.2305016120)
- [Li et al., CoAnnotating, EMNLP 2023](https://aclanthology.org/2023.emnlp-main.92/)
- [MEGAnno+, EACL 2024](https://arxiv.org/abs/2402.18050)
- [Schroeder et al., Findings of ACL 2025](https://aclanthology.org/2025.findings-acl.1323/)
- [Are Chatbots Reliable Text Annotators? Sometimes, PNAS Nexus 2025](https://academic.oup.com/pnasnexus/article/4/4/pgaf069/8100281)
- [Klie et al., Computational Linguistics 2024](https://aclanthology.org/2024.cl-3.1/)
- [Artstein and Poesio, Computational Linguistics 2008](https://aclanthology.org/J08-4004/)
- [Gebru et al., Datasheets for Datasets](https://doi.org/10.1145/3458723)

## 무엇을 카테고리화하는가

### 기존 위험 내용 category와 분리한다

`behavior_registry_v1.json`의 C01–C08은 behavior의 위험 내용 영역을 층화하기 위한
단일 top-level namespace이다. 새 taxonomy는 이를 바꾸거나 덮어쓰지 않는다.

새 namespace인 `attack_dynamics_taxonomy`는 공격의 내용이 아니라 **대화가 어떤
연결 규칙으로 다음 공격 행동을 만들었는지**를 설명하는 다중라벨 구조다. 두
namespace를 분리해야 다음 질문을 각각 검정할 수 있다.

- 어떤 위험 내용 영역인가?
- 공격자는 타깃 반응에서 무엇을 읽고 다음 turn을 어떻게 바꿨는가?

### 세 종류의 관측 단위를 합치지 않는다

| 단위 | 설명 | 주 용도 |
|---|---|---|
| Episode | 한 목표에 대한 시작부터 terminal outcome까지 | 장기 성공률, safe horizon, 예산 |
| Transition | 직전 전략·타깃 반응 신호·다음 적응 연산의 연결 | 주 taxonomy와 memory provenance |
| Memory decision | transition을 retain/merge/reject/quarantine한 사건 | 메모리 품질 및 compiler 입력 결정 |

주 annotation 단위는 `typed_adaptation_transition_with_bounded_context`이다. annotator는
최소한의 redacted 직전 대화와 다음 연산을 볼 수 있지만, 1차 판정 때 method 이름,
target 크기, split, success, judge score, defense arm은 보지 않는다. outcome은 label이
잠긴 뒤 별도 분석 단계에서 결합한다.

### 다층 다중라벨 schema

각 transition은 다음 축을 독립적으로 기록한다. 특정 공격 문구나 샘플을 category로
만들지 않는다.

| 축 | 묻는 질문 | 예시 수준 |
|---|---|---|
| `surface_form` | 요청이 어떤 형식으로 제시됐는가? | 역할 설정, 변환, 분해 |
| `dialogue_steering` | 대화 목표가 어떻게 이동했는가? | 점진화, 전제 누적, 경계 이동 |
| `response_signal` | 직전 타깃 반응의 무엇이 소비됐는가? | 거절 경계, 허용 범위, 설명 단서 |
| `adaptation_operator` | 다음 요청을 어떤 연산으로 바꿨는가? | 재표현, 세분화, 우회, 지속 |
| `memory_role` | 과거 경험이 선택에 어떤 역할을 했는가? | 재사용, 병합, 기각, 격리 |
| `evidence_strength` | 이 연결이 실제 runtime 근거인가? | explicit, inferred, unsupported |
| `defense_invariant` | 타깃이 매 turn 다시 확인할 일반 규칙은? | 대화 전체 의도 재평가 |
| `benign_exception` | 같은 신호가 정상일 때 허용 조건은? | 교육·분석·지원 맥락 |
| `predicted_adaptation` | 방어 후 예상되는 다음 우회 연산은? | payload가 아닌 operation 수준 |
| `evaluation_probe` | 이 규칙을 무엇으로 반증할 수 있는가? | 안전·도움성·과거절 동시 검사 |

앞의 여섯 축은 관측된 공격 동학을 기술한다. `defense_invariant`,
`benign_exception`, `predicted_adaptation`, `evaluation_probe`는 관측 정답이 아니라
**intervention hypothesis layer**다. 두 층을 같은 gold label로 합치면 사람이 효과가
있을 것이라 추측한 방어 규칙을 실제 관측 사실처럼 취급하게 된다. 방어 가설은 source
transition까지 추적할 수 있어야 하지만, 정답 여부는 반드시 downstream 실험으로
결정한다.

각 축에는 `none`, `uncertain`, `unmapped`를 구분한다. `unmapped`는 taxonomy 밖의 새
유형이고, `uncertain`은 근거 부족이며, `none`은 해당 현상이 관찰되지 않았다는 뜻이다.

## 데이터 생성 절차

### 0. 표본과 할당을 결과보다 먼저 고정한다

- build split의 모든 적격 transition을 census로 주석하거나, 사전등록된 HMAC 순서와
  고정 quota로 표본을 할당한다.
- 성공, 실패, 거절, timeout, fallback, no-trajectory, retain, reject, quarantine을 모두
  denominator에 남긴다.
- reviewer는 흥미로운 항목을 직접 골라 claim-bearing queue에 넣을 수 없다.
- 미완료, abstain, 도구 오류도 삭제하지 않고 terminal annotation status로 기록한다.
- category, method, outcome별 필요 표본은 outcome을 보기 전 excluded pilot과 power
  analysis로 고정한다.

### 1. Human blind-first 판정

첫 번째 사람 annotator는 LLM proposal과 결과 label을 보지 않은 상태에서 다음을
기록한다.

- 각 축의 initial label과 확신도
- 근거가 되는 redacted span 또는 event handle
- 새 code가 필요하다고 본 이유
- abstain/insufficient-context 사유
- 정상 예외와 가능한 반례

이 `human_initial`은 이후 절대 덮어쓰지 않는다. 사람에게 “LLM을 비판적으로 보라”고
말하는 것만으로 anchoring을 통제했다고 간주하지 않는다. UI 순서 자체가 suggestion을
보기 전에 initial record를 잠가야 한다.

### 2. 고정된 LLM proposal 생성

LLM은 정답자가 아니라 두 번째 annotator이자 codebook critic이다. 다음만 제안한다.

- 기존 codebook 안에서 1–3개 후보 label
- 후보마다 관측 근거와 불확실성
- merge/split 또는 `unmapped` 제안
- benign counterexample
- 짧은 defense invariant 후보

모델 ID와 exact revision, tokenizer, system/user template hash, decoding parameter, seed,
codebook hash를 고정한다. API의 moving alias만 기록한 output은 claim-bearing data에
포함하지 않는다. 가능하면 taxonomy proposal 모델과 downstream judge/defense evaluator를
다른 model family로 두어 자기평가 순환을 줄인다.

### 3. 사람의 사후 수정판정

initial label이 잠긴 뒤에만 LLM proposal을 공개한다. 같은 annotator가 다음 중 하나를
기록한다.

- `accept`: initial과 proposal이 실질적으로 일치
- `retain_human`: LLM을 보았지만 initial 유지
- `edit_after_proposal`: 일부 수정
- `reject_proposal`: LLM 제안 기각
- `abstain_after_proposal`: 추가 근거 없이는 판정 불가

`human_final`뿐 아니라 before/after label, 변경 방향, 변경 이유와 소요 시간을 모두
보존한다. 이 차이가 anchoring의 직접 측정치다.

### 4. 독립 투표와 adjudication

가장 강한 설계는 claim-bearing transition 전부를 두 사람이 서로와 LLM을 보지 않고
먼저 독립 주석하고, 고정 LLM을 세 번째 제안자로 쓰는 것이다. 비용 때문에 전수 이중
주석이 불가능하면 최소한 taxonomy induction 전부와 application data의 사전등록된
20–30% 층화 audit subset을 두 사람이 독립 주석한다. 정확한 비율은 power analysis로
G0 전에 고정한다. 희귀 category, `unmapped`, 사람–LLM 불일치, low-confidence,
category 경계 사례는 비율과 무관하게 독립 adjudicator에게 자동 전달한다.

adjudicator는 다수결 결과만 남기지 않는다. 다음을 함께 저장한다.

- 원래 두 사람의 label과 근거
- LLM proposal
- 합의 또는 비합의의 최종 상태
- codebook 조항과 결정 reason code
- codebook 변경이 필요하면 적용 가능한 split과 다음 version

주관적 경계에서의 불일치는 단순 오류가 아니라 데이터다. 공개 aggregate에는
disagreement prevalence를 포함하고, private ledger에는 개별 판정을 보존한다.

### 5. Taxonomy induction과 application을 분리한다

build를 다시 두 부분으로 나눈다.

1. `build-induction`: open coding, merge/split, 정의와 반례 작성 허용
2. `build-validation`: 동결된 codebook 적용과 신뢰도 검사만 허용

validation에서 기준을 충족하지 못하면 같은 데이터를 보고 정의를 고친 뒤 점수만 다시
내지 않는다. 변경된 codebook은 새 version이 되고, 새 validation subset 또는 excluded
pilot에서 다시 검사한다.

selection에서는 기존 codebook과 compiler 후보를 선택할 수 있지만 새 category를 만들
수 없다. confirmation에서는 수정, 재분류, prompt 선택을 모두 금지하고 새 유형을
`unmapped`로 기록해 다음 연구 version의 backlog로만 보낸다.

## Held-out 누출을 막는 핵심 규칙

leave-one-method-out(LOMO)에서 prompt compiler만 held-out method를 보지 않는 것으로는
부족하다. taxonomy를 만들 때 held-out method의 transition을 보았다면 이미 그 공격의
구조가 방어 지식에 들어간 것이다.

권장 설계는 두 층이다.

1. **Universal core:** 본 실험 전 선행연구와 permanently excluded legacy pilot로만 만든
   매우 일반적인 상위 축. 모든 fold에 공통이며 G0 전에 동결한다.
2. **Fold-specific subcodes:** 네 개 training method의 build data에서만 귀납한 하위 code.
   held-out method의 데이터는 taxonomy, guideline, annotation example, LLM prompt와
   compiler 어디에도 들어가지 않는다.

held-out method에서 기존 code에 맞지 않는 현상이 나오면 `unmapped`로 계산한다. 이를
사후에 가장 가까운 label로 강제 배정하거나 codebook을 수정하면 generalization claim이
무효가 된다. 비용은 늘지만 이 격리가 “이미 다섯 방법을 보고 만든 universal
taxonomy”라는 리뷰어 비판을 가장 직접적으로 차단한다.

별도의 target transfer 주장에도 같은 원리를 적용한다. target-specific 응답 표현을
그 target을 평가하는 fold의 category 예시나 defense prompt에 복사하지 않는다.

## 기록해야 할 provenance

각 annotation event는 append-only이며 이전 event hash와 연결한다. 최소 필드는 다음과
같다.

| 영역 | 필수 필드 |
|---|---|
| Source | run/episode/transition handle, event hash, parent hash, source-pack hash |
| Split | behavior cluster handle, fold, build phase, assignment queue/seed |
| Visibility | annotator가 실제 본 field 목록과 blinded-view hash |
| Taxonomy | namespace, taxonomy/codebook version 및 hash |
| LLM | provider, model, exact revision, tokenizer, prompt hash, decoding, seed |
| Human initial | pseudonymous reviewer handle, labels, evidence, confidence, abstain reason |
| Proposal | labels, rationale handles, uncertainty, new-code/exception proposal |
| Human final | labels, accept/edit/reject action, reason, elapsed time |
| Adjudication | independent votes, final status, reason code, adjudicator handle |
| Lifecycle | created/locked timestamps, superseding event, terminal status |

reviewer identity와 원문은 접근 통제된 private manifest에 둔다. 공개판은 payload-free
transition code, category, evidence-strength, disagreement와 aggregate만 내보낸다. raw
harmful dialogue, target response, judge rationale, source row identifier, private salt는
공개하지 않는다.

현재 GitHub Pages의 localStorage export는 공개 demo와 개인 파일럿에 적절하지만,
중앙 중복 할당, 사용자 identity, append-only merge를 보장할 수 없다. 논문용 수집은
접근 통제된 ingestion 또는 signed export를 content-addressed merge validator로 합치는
방식이 필요하다. 사이트 UI는 동일한 blind-first 흐름을 시연할 수 있지만 public site를
권위 있는 원장으로 간주하지 않는다.

## 품질과 통계 검증

### Agreement는 reliability이지 validity가 아니다

축마다 다음을 보고한다.

- 명목/서열 척도에 맞춘 Krippendorff's alpha와 cluster-bootstrap 95% CI
- 다중라벨 Jaccard, micro/macro F1, label별 confusion matrix
- hierarchical label distance와 상위/하위 category별 agreement
- 사람–사람, 사람 initial–LLM, 사람 final–LLM agreement를 서로 분리
- `unmapped`, `uncertain`, abstain, missing rate
- 희귀 category, method, outcome, target별 층화 결과

하나의 alpha threshold를 모든 축에 기계적으로 적용하지 않는다. G0 전에 각 축의
허용 기준, 재교육 조건과 중단 규칙을 정하고 CI까지 보고한다. 높은 agreement도
공유된 편향일 수 있으므로 진실성의 증거로 단독 사용하지 않는다.

운영 gate는 pilot 이전에 숫자로 고정해야 한다. 예를 들어 핵심 관측 축의 alpha,
bootstrap CI 하한, primary category당 독립 episode 수, adjudication 비율, held-out
`unmapped` 비율에 중단 기준을 둘 수 있다. `alpha >= 0.70`, CI 하한 `>= 0.60`,
adjudication `<= 30%` 같은 값은 가능한 출발점일 뿐 보편 규칙이 아니며, excluded
pilot의 난이도와 power analysis 없이 사후 채택하지 않는다. 같은 episode의 transition은
독립 표본이 아니므로 bootstrap과 신뢰구간의 resampling unit은 episode 또는 behavior
cluster로 둔다.

### Anchoring을 직접 측정한다

사전등록된 항목을 다음 arm에 무작위 할당한다.

1. `human-only`: LLM suggestion을 보지 않음
2. `llm-only`: 고정 LLM output, 사람 수정 없음
3. `human-first-assisted`: initial lock 뒤 LLM 공개와 final 판정
4. `suggestion-first diagnostic`: 일부 excluded pilot에서만 LLM을 먼저 공개

비교 지표는 정확도 하나가 아니다.

- initial→final label shift와 proposal 방향으로의 이동률
- accept/edit/reject/retain/abstain 비율
- label 분포와 category prevalence 변화
- 사람당 시간과 비용
- low-confidence 및 rare-category error
- model/seed를 바꿨을 때 proposal과 taxonomy 안정성

suggestion-first arm은 더 빠르더라도 gold 제작 방식으로 채택하지 않는다. blind-first
hybrid가 human-only와 비교해 일관성이나 비용을 개선하는지, 동시에 label 분포를
부당하게 LLM 쪽으로 이동시키지 않는지를 확인하는 진단이다.

### 최종 validity는 downstream 결과로 증명한다

category dataset의 가치는 annotation agreement가 아니라 방어에 유용한 추상화를
제공했는지로 판정한다. 동일 token budget에서 다음 prompt construction 조건을 비교한다.

1. raw-memory summarization
2. generic safety guidance
3. frequency-only category summary
4. linkage-broken transition labels
5. human-only taxonomy
6. LLM-only taxonomy
7. human-first, LLM-assisted, human-adjudicated taxonomy

주 효과는 taxonomy와 compiler가 보지 않은 공격 방법에서 live adaptive attacker가 방어
응답을 읽고 다시 적응할 때 측정한다. 최소 endpoint는 다음과 같다.

- cluster-macro strict episode ASR
- safe horizon 및 attacker calls-to-success
- benign utility non-inferiority
- gross over-refusal
- system-prompt token count와 inference cost
- explanation leakage에 따른 재적응 속도
- target model 및 method별 effect와 uncertainty

hybrid taxonomy가 label agreement만 높고 held-out ASR, 정상 성능 또는 token efficiency를
개선하지 못하면 “더 좋은 방어 데이터”라는 주장은 기각한다. 반대로 작은 taxonomy가
unseen method에서도 동일 토큰의 generic, human-only, LLM-only 조건보다 안전성을
높이고 정상 성능을 유지하면 연구적 타당성이 강해진다.

## Reviewer가 납득할 핵심 ablation

| 질문 | 필요한 비교 |
|---|---|
| LLM이 필요한가? | human-only vs human-first-assisted |
| 사람이 필요한가? | LLM-only vs human-first-assisted |
| transition 연결이 필요한가? | intact vs linkage-broken |
| 단순 빈도 효과인가? | typed trajectory vs frequency-only |
| 특정 공격 문구를 외운 것인가? | payload-free abstraction vs raw summary |
| suggestion이 사람을 끌고 갔는가? | blind-first vs suggestion-first diagnostic |
| 같은 LLM의 자기평가인가? | cross-family proposer/judge 및 evaluator 교체 |
| 공격 방법 일반화인가? | taxonomy까지 격리한 LOMO |
| 안전성만 얻고 쓸모를 잃었는가? | benign utility와 over-refusal 비열등성 |
| 토큰을 더 썼기 때문인가? | token-matched prompts와 cost curve |

## 예상되는 리뷰어 반론과 답변 조건

### “사람이 LLM을 승인했을 뿐이므로 자동화 편향이다”

사람이 suggestion을 보기 전에 initial label을 잠그고, human-only arm과 label shift를
보고해야 반박할 수 있다. final label만 남기면 이 반론을 해소할 수 없다.

### “성공한 공격만 보고 카테고리를 만들었다”

전체 고정 queue와 모든 terminal status를 denominator로 공개하고, 실패·거절·timeout·
quarantine에서도 category 분포와 방어 효과를 보고해야 한다.

### “held-out 공격을 이미 taxonomy가 봤다”

universal core는 G0 전에 legacy/선행연구로 동결하고, data-induced subcode는 fold별 네
training method로만 만든다. held-out의 새 현상은 `unmapped`로 남긴다.

### “일치도가 높다는 것이 label이 맞다는 뜻은 아니다”

동의한다. agreement는 annotation reliability로만 쓰고, validity는 held-out live attack,
benign utility, token-matched downstream ablation으로 검정한다.

### “LLM과 evaluator가 같은 편향을 공유한다”

proposer, safety judge, utility evaluator를 역할과 가능하면 model family까지 분리한다.
사람 audit와 deterministic evaluator를 함께 보고하며 한 LLM judge 결과만으로 성공을
정의하지 않는다.

### “taxonomy를 결과를 본 뒤 유리하게 수정했다”

모든 codebook diff, 이유, 적용 가능한 split과 hash를 ledger에 남긴다. build-induction
뒤에는 validation에서 정의 수정이 금지되고, selection/confirmation의 새 유형은 다음
version으로만 이동한다.

### “공개 데이터로 공격을 재현하거나 사람에게 위해를 줄 수 있다”

공개판은 payload-free projection으로 제한하고, raw context는 접근 통제한다. annotator
에게 위해 콘텐츠 노출 가능성, informed consent, opt-out, 휴식, 최소 노출 UI와 지원
절차를 제공하고 datasheet에 기록한다.

## 사전등록 gate에 통합하는 방법

기존 G0–G6를 늘릴 필요는 없고, 각 gate의 pass condition을 강화한다.

| Gate | annotation/taxonomy 요구사항 |
|---|---|
| G0 | protocol, schema, core ontology, LLM revision/prompt, assignment seed, metric과 stopping rule hash 동결 |
| G1 | 다섯 attack adapter가 같은 transition contract와 visibility receipt를 생성 |
| G2 | behavior split, annotation queue, fold, reviewer allocation과 power cap 확정 |
| G3 | permanently excluded pilot에서 UI, 교육, blind lock, reliability와 ledger 검증 |
| G4a | build-induction에서만 fold-specific subcode 생성 |
| G4b | 별도 build-validation에서 동결 codebook 적용 및 기준 통과 |
| G4c | adjudicated corpus, taxonomy와 compiler candidate hash 동결 |
| G5 | selection에서 기존 후보와 token budget만 선택; 새 category 금지 |
| G6 | sealed confirmation에서 수정·재분류·prompt 선택 금지; 새 유형은 unmapped |

gate가 실패하면 불리한 row를 삭제하거나 같은 confirmation을 다시 조정하지 않는다.
failure ledger를 남기고, 허용된 새 split 또는 새 protocol version에서 다시 시작한다.

## 데이터 공개 패키지

논문과 함께 최소 다음을 공개한다.

- protocol, frozen configs, JSON schema와 validator
- payload-free annotation JSONL과 aggregate CSV/JSON
- source/run/taxonomy/prompt hash manifest
- codebook version별 정의, 예·반례, 모든 diff와 변경 이유
- human initial, LLM proposal, human final, adjudication의 공개 가능한 projection
- assignment와 missing/abstain/terminal denominator 통계
- reliability, anchoring, cost/time, stability와 downstream result report
- intended/prohibited use, source/license, annotator 보호, blind spot, update policy를 담은
  datasheet
- 데이터를 재현하는 deterministic build script와 sealed confirmation analysis code

개별 annotator identity, raw harmful payload, private behavior row ID, split salt와 judge
rationale는 공개하지 않는다. 공개 불가능한 필드는 hash receipt와 접근 절차를 남긴다.

## Go/no-go 판정 기준

### 논문용 데이터 수집을 시작해도 되는 조건

- annotation unit, visibility mask, taxonomy namespace가 schema로 고정됨
- blind-first UI와 append-only provenance가 validator로 강제됨
- reviewer queue가 census 또는 결과 독립 고정 표본으로 생성됨
- LLM model/revision/prompt/seed가 재현 가능하게 고정됨
- human-only, LLM-only, hybrid audit arm과 adjudication 계획이 있음
- taxonomy induction/application 및 LOMO fold 격리가 확정됨
- annotator 교육, 보상, 위해 노출 보호와 datasheet 계획이 있음

### 아직 efficacy claim을 하면 안 되는 조건

- 현재 legacy pack과 localStorage 검토만 존재함
- LLM 제안을 먼저 보고 사람이 승인함
- taxonomy를 다섯 방법 전체에서 만든 뒤 한 방법을 held-out이라고 부름
- 성공 slot만 남기거나 incomplete/abstain/timeout을 삭제함
- moving API model과 기록되지 않은 prompt를 사용함
- agreement만 측정하고 downstream defense ablation이 없음
- confirmation 결과를 본 뒤 category나 compiler를 수정함

## 최종 연구 판정

이 방향은 **가능하며, 올바르게 실행하면 충분히 설득력 있는 데이터 기여가 될 수
있다**. 다만 현재 자료는 “논문용 데이터가 완성됐다”가 아니라 “좋은 파일럿과 수집
도구의 출발점이 있다”는 상태다.

가장 강한 논문 프레이밍은 다음과 같다.

> We introduce a preregistered, LLM-assisted and human-adjudicated process for
> deriving a transition-level taxonomy of adaptive attack dynamics. The process
> preserves blind human judgments and measures suggestion-induced anchoring,
> then tests whether the resulting abstractions compile into low-token defenses
> that transfer to unseen adaptive attack methods without degrading benign
> utility.

리뷰어가 최종적으로 인정할 근거는 “사람과 LLM이 같이 봤다”가 아니다. **누가 무엇을
언제 봤는지 재현할 수 있고, 불일치와 실패를 삭제하지 않았으며, held-out 공격의 정보를
taxonomy 단계부터 차단했고, 그 결과가 실제 방어의 안전성–정상성–토큰 비용에서
재현됐는가**이다.
