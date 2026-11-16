# AAMD LLM-First Human Review Protocol v2

**Protocol ID:** `aamd-llm-first-human-review-v2`
**상태:** prospective protocol candidate; claim-bearing 실행 전 config, schema, validator,
assignment manifest, 분석 계획과 hash 동결 필요
**적용 범위:** AAMD의 transition-level attack-dynamics annotation과 defense-affordance
review
**대체하지 않는 것:** 기존 v1 문서, v1 pilot export, v1 event chain과 그 hash

## 문서의 결론

AAMD v2의 기본 annotation 흐름은 다음과 같다.

```text
frozen offline LLM proposal
  -> primary human accept/edit/reject/abstain
  -> same-proposal independent secondary review
     (primary vote, rationale, confidence, timing hidden)
  -> adjudication
```

LLM은 사람이 검수할 초안을 먼저 만든다. Primary와 secondary reviewer는 동일한 task
projection, 동일한 codebook, 동일한 LLM proposal bytes와 hash를 보고 각각 독립적으로
판정한다. Secondary에게는 primary의 label, disposition, 근거, confidence, 작업 상태와
소요 시간을 공개하지 않는다. Adjudicator는 두 사람의 잠긴 review를 비교해 최종 상태를
기록하되, LLM proposal이나 앞선 사람 판정을 덮어쓰지 않는다.

이 방식은 일반적인 **LLM-assisted, human-reviewed** 데이터 구축 절차다. Annotation
순서 자체를 연구적 novelty로 주장하지 않으며, 사람이 검수했다는 사실만으로 객관적
ground truth, 편향 제거 또는 anchoring 통제를 주장하지 않는다. 연구의 주된 기여는
provenance-complete adaptive attack memory, attack-side causal validation, held-out defense
actionability와 safety–utility 평가에 둔다.

## 1. 허용되는 주장과 금지되는 주장

### 1.1 허용되는 주장

다음과 같이 사실에 한정해 표현할 수 있다.

> 사전등록된 표본에서 versioned LLM proposal을 offline으로 생성·동결하고, 서로의
> 판정을 보지 않는 두 사람이 동일 proposal을 독립 검수한 뒤 불일치를 조정했다. LLM
> proposal, 두 human review, adjudication과 모든 provenance를 보존했으며, annotation
> reliability, expert-audit accuracy와 held-out downstream defense actionability를 별도로
> 평가했다.

다음 조건이 실제로 충족됐을 때만 `independent secondary review`, `adjudicated`,
`expert-audited`, `held-out validated`라는 표현을 사용한다.

- primary와 secondary가 서로 다른 검증된 reviewer identity다.
- secondary가 primary vote와 그 파생 정보를 받지 않았다.
- 두 reviewer에게 전달된 task projection과 proposal bytes/hash가 동일하다.
- adjudication event와 원래 두 review가 append-only ledger에 함께 남아 있다.
- expert audit과 held-out downstream validation을 주장하는 경우 해당 실험이 실제로
  완료됐고, 실패·누락 denominator까지 보고됐다.

### 1.2 금지되는 주장

다음 표현은 이 protocol만으로 뒷받침되지 않는다.

- “사람이 확인했으므로 LLM label은 객관적 ground truth다.”
- “두 사람이 동의했으므로 label validity가 증명됐다.”
- “LLM suggestion에 의한 anchoring 또는 automation bias를 제거했다.”
- “사람이 proposal을 보기 전 독립 label을 만들었다.”
- “initial-to-final shift를 측정했으므로 anchoring의 인과 효과를 추정했다.”
- “LLM-first가 human-only 또는 blind-first보다 정확하거나 우수하다.”
- “한 model family가 생성·검수 보조·downstream 평가를 모두 했지만 독립 검증과
  동등하다.”

Anchoring의 인과 효과를 별도로 주장하려면 이 production workflow와 분리된
사전등록 randomized diagnostic study가 필요하다. 그런 study가 없으면 acceptance,
edit 또는 disagreement rate는 기술 통계일 뿐 anchoring estimand가 아니다.

## 2. Annotation 대상과 층 분리

주 annotation unit은 `typed_adaptation_transition_with_bounded_context`다. 각 task에는
payload-free 또는 접근 통제된 최소 context와 다음 정보가 포함될 수 있다.

- 직전 state와 redacted evidence handle
- target response에서 소비된 추상 signal
- 다음 adaptation operation 또는 memory decision
- 적용할 codebook version과 allowed labels
- LLM proposal과 proposal-level evidence/uncertainty

다음 세 층은 같은 gold namespace로 합치지 않는다.

1. **Observed dynamics:** response signal, adaptation operator, memory role,
   evidence strength처럼 runtime evidence로 확인할 수 있는 관측 축
2. **Human-reviewed interpretation:** 관측 축에 대한 LLM proposal과 사람의 review
3. **Intervention hypothesis:** defense invariant, benign exception, predicted
   readaptation, evaluation probe처럼 downstream 실험으로 반증해야 하는 가설

`defense_invariant` 등 intervention hypothesis는 human review를 통과해도 관측 정답이
되지 않는다. 최종 validity는 held-out live defense evaluation에서 판단한다.

## 3. 역할과 분리 규칙

| 역할 | 책임 | 반드시 지킬 분리 |
|---|---|---|
| Proposal generator | 동결된 입력에서 LLM proposal 생성 | human review와 downstream outcome을 보지 않음 |
| Primary reviewer | proposal을 accept/edit/reject/abstain | secondary/adjudicator 역할과 분리 |
| Secondary reviewer | 동일 proposal을 독립 검수 | primary vote·rationale·status·timing을 보지 않음 |
| Adjudicator | 잠긴 두 review를 비교하고 terminal status 결정 | 같은 task의 primary/secondary와 분리 |
| Data administrator | assignment, access, export와 ledger 운영 | reviewer/adjudicator 역할과 분리 |
| Analyst | 동결된 analysis plan으로 aggregate 계산 | confirmation label이나 codebook을 사후 수정하지 않음 |

Claim-bearing task에서는 한 사람이 같은 task의 역할을 겸할 수 없다. Pseudonym만 다르고
실제 identity가 같은 경우도 겸임으로 본다. Admin과 reviewer의 분리는 접근 통제와
감사 로그 양쪽에서 강제한다.

## 4. 결과보다 먼저 고정할 것

Claim-bearing collection 전에 다음을 G0/G2 artifact로 동결한다.

- source cohort, eligibility, exclusion과 denominator 규칙
- task 생성 code와 ordered assignment manifest
- split/fold commitment와 private salt
- annotation unit, codebook, label 정의, 예·반례
- visibility mask와 각 역할별 field allowlist
- LLM provider, model ID, exact revision/checkpoint와 tokenizer
- system/user template의 exact bytes와 hash
- decoding parameters, seed, tool version, retry와 failure policy
- input projection hash, proposal bytes와 `proposal_sha256`
- reviewer allocation, task 순서, adjudicator allocation
- primary/secondary/adjudication reason code
- reliability, audit, missingness, time/cost와 downstream metric
- stopping rule, exclusion rule, multiplicity와 confidence interval 방법

흥미로운 row를 사람이 골라 claim-bearing queue에 넣을 수 없다. Census 또는 결과를 보지
않고 만든 고정 표본을 사용하며, incomplete, abstain, tool error와 adjudication failure도
denominator에서 삭제하지 않는다.

## 5. Stage 0 — Frozen offline LLM proposal

### 5.0 고정된 32B proposer 계약

V2의 1차 proposal generator는
`research/configs/aamd_llm_first_labeler_32b_v1.json`에 고정한
`Qwen/Qwen2.5-VL-32B-Instruct` 32B 한 개 모델이다. Revision 후보는
`7cfb30d71a1f4f49a57592323337a4a4727301da`, prompt exact-byte hash는
`cfad4c64a0f0afa97db52b779e29f86220df6fd8b6a7fb6f5989f1d8bf27eab2`, canonical
decoding config hash는
`3725e1f6f82d2a4b469375f668431fd7c406314f0e3b57ac6d02b7af9e887add`다.

이 32B 모델은 후보 label, evidence handle, uncertainty와 T4 defense-affordance를
제안하는 proposer다. Ground truth, adjudicator, safety judge 또는 utility evaluator가
아니며, 사람의 accept도 객관적 정답을 뜻하지 않는다. 비교 실험 없이 작은 모델보다
정확하다는 주장도 하지 않는다. 같은 confirmation run에서 proposer checkpoint를
adjudicator나 downstream judge로 재사용하지 않는다.

현재 revision 상태는 `candidate_needs_G0_attestation`이다. 따라서 이 계약은 synthetic와
pilot proposal에는 사용할 수 있지만 claim-bearing 생성은 시작하지 않는다. G0에서는
weights snapshot, tokenizer, chat template, prompt bytes, decoding JSON, container/library,
generator code, input/output hash와 retry/repair policy를 동결해 `g0_attested` 상태의 새
manifest를 만든다. 검토된 manifest SHA-256을 새 Worker source version에 trusted commitment로
커밋하고 proposal의 `g0_attestation_hash`와 exact match시킨다. 별도로 모든 task,
source hash와 exact proposal bytes를 포함하는 canonical claim-bundle SHA-256도 Worker
source에 커밋한다. 두 commitment가 모두 맞아야 하므로 유효한 model attestation을 임의
proposal에 재사용할 수 없다. Bundle 내부의 `g0_attested` 문자열만으로 gate를 열지
않는다. 현재 두 commitment는 모두 `null`이라 v2 claim-bearing import는 fail-closed다.
Legacy V1의 신규 claim-bearing import도 허용하지 않는다. 이미 생성된 pilot artifact를
소급해서 claim-bearing으로 바꾸지 않는다.

### 5.1 생성 시점

모든 claim-bearing LLM proposal은 human review가 시작되기 전에 offline으로 생성한다.
Review 도중 reviewer 행동, disagreement, preliminary label 또는 downstream outcome을 보고
proposal을 재생성하거나 보강하지 않는다. Human study runtime에서 live model endpoint를
호출하지 않는다.

### 5.2 입력과 출력

LLM은 정답자가 아니라 초안 제안자다. 최소 출력은 다음과 같다.

- codebook 안의 후보 label 또는 `none`/`uncertain`/`unmapped`
- 후보별 evidence handle과 짧은 근거
- proposal uncertainty 또는 abstention
- 필요할 때 merge/split/new-code suggestion
- intervention-hypothesis task의 defense invariant, benign exception,
  predicted readaptation, evaluation probe 초안

LLM output은 parse 후 의미가 바뀌지 않도록 canonical JSON과 원 exact bytes를 함께
commit한다. Parser repair가 발생하면 원 output, repair rule/version과 repaired output의
hash를 모두 남긴다. 사람이 직접 고친 proposal을 LLM 원출력처럼 저장하지 않는다.

### 5.3 생성 실패

Timeout, malformed output, policy refusal, missing model revision 또는 provenance 불완전은
명시적 `proposal_status`로 남긴다. 이 protocol의 기본 claim-bearing workflow는 frozen
proposal이 있어야 하므로 proposal이 유효하지 않은 task는 조용히 human-only row로
바꾸지 않는다. 사전등록된 정책에 따라 `proposal_unavailable` terminal status로 남기거나,
결과를 보기 전에 정한 deterministic retry budget 안에서만 재시도한다.

## 6. Stage 1 — Primary human review

Primary reviewer는 task evidence, codebook과 frozen proposal을 처음부터 함께 본다. 별도의
proposal-hidden initial label을 만들지 않는다. Reviewer는 다음 disposition 중 정확히
하나를 기록한다.

| Disposition | 의미 |
|---|---|
| `accept` | proposal을 근거와 codebook에 부합한다고 판단해 그대로 채택 |
| `edit` | 일부 label, evidence mapping 또는 hypothesis field를 수정해 채택 |
| `reject` | proposal이 근거 부족, codebook 위반 또는 잘못된 해석이라 판단해 기각 |
| `abstain` | 주어진 context만으로 책임 있는 판정이 불가능 |

`edit`와 `reject`에는 수정 label 또는 명시적 no-label 상태, evidence handle과 reason code가
필수다. `accept`도 단순 클릭으로 끝내지 않고 최소한 evidence sufficiency와 codebook
conformance 확인을 기록한다. `abstain`에는 `insufficient_context`, `ambiguous_codebook`,
`harm_exposure_limit`, `tool_error` 같은 원인을 남긴다.

Primary event에는 최소 다음을 기록한다.

- pseudonymous reviewer handle과 role receipt
- assignment/task/proposal/codebook/visibility-mask hash
- disposition과 final proposed labels
- evidence handle, reason code, confidence
- T4라면 네 intervention-hypothesis field
- started/locked timestamp와 elapsed time
- previous event hash와 current event hash

잠긴 primary review는 수정하거나 삭제하지 않는다. 오류 정정은 원 event를 남긴 새
superseding event로만 가능하며, claim-bearing analysis 포함 여부는 사전등록된 correction
policy를 따른다.

## 7. Stage 2 — Same-proposal independent secondary review

Secondary reviewer는 primary와 정확히 같은 task projection, codebook version, proposal
bytes와 proposal hash를 받는다. 이는 proposal의 효과를 숨기기 위한 blind review가 아니라,
**동일한 LLM-first workflow가 다른 사람에게 얼마나 재현되는지** 측정하는 review다.

Secondary에게는 다음을 전송하거나 UI source에 포함하지 않는다.

- primary disposition과 labels
- primary evidence selection, rationale와 confidence
- primary의 세부 처리 상태, timestamp와 elapsed time
- primary와의 agreement/disagreement hint
- adjudication queue 진입 여부 또는 trigger reason

Secondary도 `accept`, `edit`, `reject`, `abstain` 중 하나와 독립 label, evidence, reason,
confidence를 기록한다. Primary 완료 뒤 secondary task가 활성화될 수는 있지만, UI에는
“primary가 동의/수정했다” 같은 파생 신호를 표시하지 않는다.

Claim-bearing core field에는 secondary review가 필수다. 비용 때문에 일부 secondary
review만 수행하는 별도 pilot은 가능하지만, 그 결과를 전수 double-review corpus처럼
표현하지 않으며 sampling rule과 missing denominator를 공개한다.

## 8. Stage 3 — Adjudication

Adjudicator는 frozen proposal과 잠긴 primary/secondary review를 모두 본다. 다음 terminal
status 중 하나를 기록한다.

- `agreement_confirmed`: 두 review가 사전 정의된 동치 규칙상 일치
- `resolved`: 불일치를 codebook과 evidence로 해결
- `pending`: 추가 context나 codebook 결정 없이는 해결 불가
- `disagreement_retained`: 합리적 복수 해석으로 불일치를 그대로 보존
- `escalated`: 안전, 윤리, source integrity 또는 protocol 문제로 상위 검토 필요

Adjudicator는 단순 다수결만 남기지 않는다. 최종 label 또는 label distribution,
codebook clause, evidence handle, reason code와 불일치 유형을 함께 기록한다. 새 category가
필요하면 현재 confirmation row를 사후 재분류하지 않고 `unmapped`와 다음 codebook
version backlog로 보낸다.

Adjudication은 원 proposal과 두 review를 덮어쓰지 않는다. Public release에는 허용된
projection만 내보내더라도 private ledger에는 전체 chain과 hash commitment를 보존한다.

## 9. Visibility contract

Proposal 순서와 outcome blinding은 별개다. Reviewer가 LLM proposal을 먼저 보더라도 다음
downstream 정보는 dynamics annotation 중 가린다.

| Field | Proposal generator | Primary | Secondary | Adjudicator |
|---|---:|---:|---:|---:|
| Task projection/evidence handles | 허용 | 허용 | 동일 bytes 허용 | 허용 |
| Frozen LLM proposal | 생성 | 허용 | 동일 bytes 허용 | 허용 |
| Primary review | 금지 | 자신의 event만 | 금지 | 허용 |
| Secondary review | 금지 | 금지 | 자신의 event만 | 허용 |
| Attack method name | 기본 금지 | 금지 | 금지 | 필요 시 제한 공개 |
| Target parameter scale | 기본 금지 | 금지 | 금지 | 필요 시 제한 공개 |
| Actual split/fold name | 금지 | 금지 | 금지 | 금지 |
| Strict success/judge score/reason | 금지 | 금지 | 금지 | dynamics 조정에는 기본 금지 |
| Defense arm/downstream outcome | 금지 | 금지 | 금지 | 금지 |
| Raw harmful payload/response | handle만 | 최소권한 | 최소권한 | 필요 시 접근 통제 |

각 API response와 export는 역할별 allowlist 검사를 통과해야 한다. UI에서 CSS로 숨기는
것은 blindness나 access control이 아니다. 금지 field는 브라우저에 전송하지 않는다.

## 10. Append-only provenance와 최소 record

각 task는 다음 event chain을 가진다.

```text
task_frozen
  -> llm_proposal_frozen
  -> primary_review_locked
  -> secondary_review_locked
  -> adjudication_locked
```

최소 provenance는 다음과 같다.

| 영역 | 필수 내용 |
|---|---|
| Protocol | `aamd-llm-first-human-review-v2`, schema/version/hash |
| Source | run, episode, transition handle와 source event/hash |
| Assignment | cohort, queue, ordinal, reviewer-role allocation commitment |
| Visibility | role, visible-field allowlist, projection/hash, access receipt |
| Codebook | taxonomy namespace, version, exact hash |
| LLM | provider, exact model revision/checkpoint, tokenizer, templates, decoding, seed, tool/parser version |
| Proposal | canonical payload, exact-byte hash, labels, evidence, uncertainty, status |
| Primary | identity pseudonym, disposition, labels, evidence, confidence, reason, timing, event hash |
| Secondary | 동일 필드와 same-proposal receipt, primary-hidden receipt |
| Adjudication | terminal status, final labels/distribution, evidence, clause, reason, event hash |
| Lifecycle | created/locked timestamps, previous hash, superseding event와 terminal status |

Proposal과 사람 review를 합친 final row만 저장하면 이 protocol을 충족하지 못한다. 각 단계
event와 visibility receipt를 별도로 재구성할 수 있어야 한다.

## 11. Quality control

### 11.1 사전 교육과 qualification

- Excluded pilot로 codebook 교육, 경계 사례와 abstention 사용법을 확인한다.
- Qualification item은 claim-bearing denominator에 포함하지 않는다.
- 교육 중 proposal 오류를 발견하는 연습을 포함하되, 본 task의 정답이나 분포를 암시하지
  않는다.
- 보상은 accept rate나 특정 label과 연동하지 않는다.

### 11.2 자동 validator

Validator는 최소 다음을 fail-closed로 검사한다.

- proposal이 human review 시작 전에 생성·동결됐는가?
- model/prompt/seed/codebook/input/output hash가 완전한가?
- primary와 secondary identity가 다른가?
- 두 reviewer가 같은 task/proposal bytes를 받았는가?
- secondary response에 primary-derived field가 없었는가?
- 모든 non-abstain review에 label, evidence와 reason이 있는가?
- event order, previous hash, role과 expected version이 일치하는가?
- missing, incomplete, error와 abstain이 denominator에 남아 있는가?
- confirmation 결과를 본 뒤 proposal, codebook 또는 label이 수정되지 않았는가?

### 11.3 독립 품질 감사

같은 proposal을 본 두 사람의 agreement는 workflow reproducibility이지 독립 truth가
아니다. Accuracy 또는 automation-bias risk를 평가하려면 production label과 분리된
사전등록 stratified expert-reference subset을 둔다. Expert reference는 가능하면 proposal과
production votes를 보지 않고 source evidence와 codebook만으로 작성하며, production
workflow와 다른 identity가 담당한다.

Expert audit가 없으면 논문에 그 사실을 명시하고 다음과 같이 한정한다.

> We evaluate reviewer agreement and downstream actionability, but do not claim
> independently established annotation accuracy or an unbiased human reference.

### 11.4 안전과 참여자 보호

- IRB 승인 또는 면제, informed consent, 철회와 보존 정책을 기관 기준에 맞게 확정한다.
- 최소 노출 UI, 휴식, opt-out, harm-exposure limit와 지원 절차를 제공한다.
- Reviewer identity, raw harmful text와 private source linkage를 공개 export에서 제거한다.
- 연구 참여 거부나 abstention이 보상 또는 역할에 불이익을 주지 않도록 한다.

## 12. 사전등록 지표

### 12.1 Workflow와 coverage

- eligible task completion rate
- proposal generation/parse/tool-error rate
- primary/secondary completion과 missing rate
- `accept`/`edit`/`reject`/`abstain` 비율
- adjudication status와 escalation rate
- task당 시간, 인건비, LLM token/call cost

### 12.2 Reliability

- primary–secondary exact agreement
- 축별 Krippendorff's alpha와 cluster-bootstrap 95% CI
- multilabel Jaccard, micro/macro F1와 label별 confusion matrix
- hierarchical label distance
- evidence-handle overlap과 reason-code agreement
- rare label, `unmapped`, low-confidence, method와 behavior domain별 층화 결과

두 reviewer가 같은 proposal을 보므로 이를 `human-only inter-annotator agreement`라고 부르지
않는다. 정확한 명칭은 `same-proposal primary–secondary review agreement`다.

### 12.3 Proposal quality와 human correction

- primary와 secondary 각각의 proposal accept/edit/reject/abstain rate
- proposal label 대비 reviewed label의 edit distance
- missing evidence, wrong codebook boundary, unsupported inference, over-specificity,
  under-specificity와 unsafe leakage 같은 오류 유형
- proposal uncertainty와 human disposition/calibration의 관계
- exact model revision, category와 difficulty별 오류율

이 지표는 proposal의 검수 결과를 설명하지만, proposal을 보지 않았을 때 사람이 무엇을
선택했을지 추정하지 않는다.

### 12.4 Independent audit와 downstream validity

Expert-reference subset이 있으면 accuracy/F1, calibration, systematic error와 CI를 별도
보고한다. 최종 데이터의 연구적 validity는 다음 held-out endpoint로 판단한다.

- unseen-method live-adaptive strict episode ASR
- safe horizon과 attacker calls-to-success
- benign utility non-inferiority와 gross over-refusal
- token/call/latency cost
- linkage-broken, unrelated, raw-summary와 generic control 대비 효과
- target/model family와 behavior domain별 heterogeneity와 uncertainty

Agreement가 높아도 held-out defense actionability가 없으면 “방어에 더 유용한 데이터”라는
주장을 기각한다.

## 13. 통계 단위와 분석 원칙

같은 episode의 여러 transition을 독립 표본으로 세지 않는다. Confidence interval과
bootstrap의 resampling unit은 사전등록된 episode 또는 semantic behavior cluster로 둔다.
Reviewer별 반복 측정도 고려하며, 결측을 complete-case로 조용히 삭제하지 않는다.

Primary 분석 전에 다음을 고정한다.

- 핵심 축과 secondary 축
- 최소 표본과 power 또는 precision 목표
- agreement/accuracy/coverage threshold와 중단 규칙
- multiple comparison 처리
- missing, abstain, pending와 tool error 처리
- adjudicated label과 label distribution 중 어느 것을 downstream에 사용할지
- reviewer, episode와 behavior cluster를 반영한 uncertainty 계산법

`alpha >= 0.70` 같은 숫자를 보편 기준으로 사후 채택하지 않는다. Excluded pilot과
사용 목적에 맞춘 threshold를 confirmation 전에 고정한다.

## 14. 알려진 한계

1. **Automation bias:** 사람은 먼저 본 LLM proposal에 끌릴 수 있다. 이 protocol은 그
   가능성을 제거하거나 인과적으로 측정하지 않는다.
2. **Correlated error:** primary와 secondary가 동일 proposal을 보므로 서로 독립적으로
   클릭해도 같은 model 오류를 공유할 수 있다.
3. **Review는 ground truth가 아님:** 높은 accept rate와 human agreement는 정확성 또는
   downstream 유효성의 충분조건이 아니다.
4. **Codebook dependence:** label은 동결된 taxonomy와 제공된 context의 경계를 반영한다.
   다른 codebook이나 더 많은 context에서 판정이 달라질 수 있다.
5. **Model/version dependence:** proposer revision, prompt와 decoding이 바뀌면 proposal
   분포와 human correction workload도 바뀔 수 있다.
6. **Payload-free information loss:** 공개 projection만으로 세밀한 dialogue semantics를
   판정하기 어려운 row가 있으며, 이를 억지로 label하지 않고 abstain/uncertain으로 남긴다.
7. **Reviewer population:** 특정 언어, 전문성, 교육과 보상 체계에서 얻은 결과를 모든
   사람이나 domain으로 일반화할 수 없다.
8. **Evaluator circularity:** proposer와 downstream judge가 같은 family면 공유 편향이
   생길 수 있다. 역할과 가능하면 model family를 분리한다.
9. **Adjudication subjectivity:** 제3자 조정도 객관적 진실을 보장하지 않는다. 원
   disagreement와 reason을 삭제하지 않는다.

## 15. Split, taxonomy와 confirmation 보호

- Taxonomy induction은 `build-induction`에서만 허용한다.
- 동결된 codebook은 `build-validation`에서 적용하고 reliability를 평가한다.
- Selection에서는 기존 taxonomy와 compiler 후보만 고를 수 있다.
- Confirmation에서는 category 생성, relabeling, proposal 재생성과 prompt 재선택을
  금지한다.
- Leave-one-method-out fold의 held-out method는 taxonomy example, proposal prompt,
  codebook induction과 compiler 입력에도 들어가지 않는다.
- Held-out에서 새 유형이 나오면 가장 가까운 label로 사후 강제하지 않고 `unmapped`로
  남긴다.

LLM-first workflow로 바뀌어도 이 누출 통제는 약화하지 않는다.

## 16. Release package

논문과 함께 최소 다음을 공개하거나 접근 가능한 audit receipt로 제공한다.

- 이 protocol과 exact protocol/config/schema hash
- payload-free task와 annotation projection
- frozen proposal model/prompt/decoding/codebook manifest
- proposal, primary, secondary와 adjudication의 공개 가능한 event projection
- assignment, completion, missing, abstain와 terminal denominator
- reliability, proposal correction, expert audit, time/cost report
- held-out downstream validation과 negative/null result
- taxonomy/codebook diff와 version policy
- intended/prohibited use, participant protection, known bias와 update policy를 포함한
  datasheet
- deterministic validator와 analysis code

개별 reviewer identity, raw harmful payload, target response, private split salt와 judge
rationale는 공개하지 않는다. 공개할 수 없는 필드는 content hash, access policy와 audit
절차를 남긴다.

## 17. v1과의 호환성 및 migration

기존 v1 blind-first protocol과 그 export는 역사적 provenance로 보존한다. v2를 적용하기
위해 v1 event를 덮어쓰거나 같은 event type의 의미를 바꾸지 않는다.

### 17.1 의미상 비호환인 항목

| v1 | v2 | 처리 원칙 |
|---|---|---|
| `human_initial` | 없음 | v2 primary review로 재해석 금지 |
| `proposal_reveal` | proposal은 review 전 offline 동결·처음부터 표시 | reveal event를 v2 proposal event로 자동 변환 금지 |
| `human_final` | `primary_review` | 별도 schema/version으로 저장 |
| proposal-blind independent vote | same-proposal secondary review | 서로 다른 estimand로 보고 |
| initial-to-final anchoring metric | proposal correction/disposition metric | 수치 결합 금지 |
| `human_llm_coadjudication_chain` | `llm_first_human_review_chain` | role/type version 분리 |

### 17.2 Dataset 결합 규칙

- v1과 v2 row를 같은 annotation condition으로 pooling하지 않는다.
- Aggregate에는 protocol ID별 row 수, missingness, agreement와 downstream 결과를 분리한다.
- v1 pilot row를 v2 claim-bearing denominator에 소급 포함하지 않는다.
- 동일 source transition을 v2에서 다시 검수하면 새 assignment/task/event ID와 lineage
  link를 만들고 원 v1 event는 그대로 둔다.
- Config, schema, validator, UI stage machine과 analysis plan에 새 protocol/version을
  명시한다.
- G0 이후 protocol을 바꾸는 경우 기존 hash를 수정하지 않고 새 run/profile과 freeze
  artifact를 만든다.

현재 v1이 아직 claim-bearing freeze 전이라도 semantic contract가 크게 바뀌므로 v2
protocol ID와 event/schema version을 사용하는 것이 안전하다.

## 18. Go/no-go gate

### 시작 조건

- `aamd-llm-first-human-review-v2`가 config와 schema에서 exact match로 고정됨
- 1차 proposer가 고정된 `Qwen/Qwen2.5-VL-32B-Instruct` 32B exact revision이고,
  claim-bearing run에서는 revision 상태가 `g0_attested`임
- frozen offline proposal과 provenance validator가 통과함
- primary/secondary same-proposal delivery와 primary-hidden secondary response가 통합
  테스트로 검증됨
- reviewer/admin/adjudicator identity separation이 server와 ledger에서 강제됨
- assignment, missingness, adjudication와 analysis plan이 사전등록됨
- IRB/면제, consent, 보상, 위해 노출과 보존 정책이 확정됨
- expert audit을 주장한다면 독립 reference subset과 분석 계획이 동결됨
- held-out taxonomy/consumer/downstream evaluation 경계가 동결됨

### claim 중단 또는 강등 조건

- proposal이 review 시작 후 생성·수정됐거나 exact revision/provenance가 없음
- proposal 생성 시각이 import보다 미래이거나, trusted G0·canonical claim-bundle
  commitment 중 하나라도 일치하지 않음
- Legacy protocol로 신규 claim-bearing bundle을 import함
- secondary가 primary vote 또는 파생 신호를 볼 수 있었음
- 두 reviewer에게 다른 proposal 또는 task projection이 전달됨
- accept만 저장하고 edit/reject/abstain, evidence와 reason을 보존하지 않음
- incomplete, abstain, pending, tool error 또는 불리한 row를 삭제함
- adjudication이 원 vote를 덮어씀
- expert reference 없이 annotation accuracy 또는 bias 제거를 주장함
- agreement만으로 defense validity를 주장함
- confirmation 결과를 본 뒤 taxonomy, label, proposal 또는 compiler를 수정함

Gate 실패 시 불리한 event를 삭제하거나 같은 protocol ID의 history를 재작성하지 않는다.
Failure ledger를 남기고 수정된 새 version/run에서 다시 시작한다.

## 19. 권장 논문 문구

### 19.1 한국어 methods 문구

> 각 transition에 대해 동결된 LLM이 후보 label, 근거와 불확실성을 offline으로 먼저
> 생성했다. 서로 다른 두 reviewer가 동일한 task projection과 동일 proposal을 보되
> 서로의 판정을 보지 않고 accept, edit, reject 또는 abstain을 기록했다. 제3의
> adjudicator가 잠긴 두 review의 일치와 불일치를 codebook 및 evidence에 따라
> 조정했다. Proposal, 두 human review와 adjudication은 별도 append-only event로
> 보존했다. 이 절차는 LLM-assisted human review이며, proposal-blind human annotation
> 또는 anchoring control로 해석하지 않는다.

### 19.2 English methods wording

> For each transition, a frozen LLM generated an offline proposal containing
> candidate labels, evidence, and uncertainty. Two distinct reviewers received
> the same task projection and exact proposal, but not each other's decisions,
> and independently recorded an accept, edit, reject, or abstain disposition.
> A third adjudicator resolved or retained disagreements against the frozen
> codebook and evidence. The proposal, both human reviews, and adjudication were
> preserved as separate append-only events. We treat this as an LLM-assisted,
> human-reviewed workflow, not as proposal-blind human annotation or a control
> for suggestion-induced anchoring.

### 19.3 Limitations wording

> Because both reviewers observed the same LLM proposal, their errors may be
> correlated and their agreement does not establish an unbiased human ground
> truth. Unless supported by a separate proposal-blind expert audit, we report
> workflow reproducibility and downstream actionability rather than independent
> annotation accuracy or a causal estimate of anchoring.

### 19.4 Contribution wording

> The annotation workflow is a conventional LLM-first human-review procedure.
> Our claimed contribution is the provenance-complete adaptive-attack-memory
> resource and its causal and held-out defense evaluation, rather than the
> ordering of model and human annotation itself.

## 최종 판정

이 v2 protocol은 운영 효율을 위해 LLM이 먼저 초안을 만들고 사람이 검수하는 일반적인
방식을 채택한다. 그 대가로 사람의 proposal-blind 판단과 anchoring 인과 추정은 포기한다.
따라서 proposal provenance, 독립적인 same-proposal 이중 검수, append-only adjudication,
별도 expert audit과 held-out downstream validation을 통해 품질을 평가하고, 남는 automation
bias와 correlated error를 논문과 datasheet에 명시해야 한다.
