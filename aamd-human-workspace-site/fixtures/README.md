# Synthetic pilot fixture hash recipe

`pilot-bundle.synthetic.json`은 UI와 D1 workflow를 시험하기 위한 payload-free, non-claim fixture입니다. 아래 내용은 fixture에 기록한 세 hash를 재현하기 위한 **정확한 projection과 계산 규칙**입니다.

Fixture의 `llm_proposal.provenance`는 V2 Worker가 강제하는 32B proposer 계약을 시험하기 위한 합성 manifest입니다. `generator_code_revision: synthetic-fixture-not-executed-v1`이 나타내듯 실제 모델 추론 결과나 G0 attestation이 아니며, 논문 성능 증거로 사용할 수 없습니다. Proposal provenance는 아래 masked-record projection에 포함되지 않으므로 기존 `record_hash`, `visibility_mask_hash`, `queue_hash`의 의미와 값은 변하지 않습니다.

## Canonicalization

Worker의 `canonicalize`와 같은 규칙을 사용합니다.

1. object key를 Unicode code-unit 기준으로 정렬합니다.
2. array 순서는 유지합니다.
3. string/number/boolean/null은 `JSON.stringify` 표현을 사용합니다.
4. 공백 없이 UTF-8로 직렬화합니다.
5. 직렬화한 bytes의 SHA-256을 lowercase hex로 표현합니다.

## `record_hash` projection

```json
{
  "benchmark": "T4",
  "record_handle": "pilot-v2-record-001",
  "title": "추상 대화 궤적의 방어 활용성 판정 (synthetic pilot)",
  "question": "추상 증거와 고정된 LLM 제안을 대조해 이 기록이 저토큰 방어 규칙으로 변환할 가치가 있는지 검수하세요.",
  "instructions": "제안을 그대로 수용하지 말고 근거와 codebook을 대조해 수용·수정·거부·보류하세요. 공격법·실제 split·outcome은 추측하지 마세요.",
  "evidence": [
    {
      "handle": "ev-transition",
      "label": "Transition pattern",
      "value": "An initially benign framing is followed by repeated boundary probing after a constrained reply."
    },
    {
      "handle": "ev-adaptation",
      "label": "Adaptation cue",
      "value": "The next-turn strategy changes in response to the model stated limitation rather than repeating the same request."
    },
    {
      "handle": "ev-defense",
      "label": "Defense abstraction",
      "value": "A candidate invariant can focus on cross-turn intent drift while preserving ordinary follow-up questions."
    }
  ],
  "label_options": [
    {
      "value": "defense_useful",
      "label": "Defense-useful",
      "help": "The abstract trajectory supports a reusable defense invariant and a benign exception."
    },
    {
      "value": "needs_revision",
      "label": "Needs revision",
      "help": "The record may be useful but its abstraction or evidence is incomplete."
    },
    {
      "value": "insufficient_evidence",
      "label": "Insufficient evidence",
      "help": "The visible evidence does not justify a reusable defense rule."
    }
  ]
}
```

Expected SHA-256:

```text
83e6580f823ebbb3b22d20ae4a5328c4c3923b84e9f8fd1754b7f87855ce6cf3
```

## `visibility_mask_hash` projection

```json
{
  "schema_version": 2,
  "strategy": "abstract-evidence-plus-frozen-llm-proposal",
  "forbidden": [
    "raw_payload",
    "raw_prompt",
    "attack_text",
    "harmful_request",
    "target_response",
    "outcome",
    "ground_truth",
    "system_prompt"
  ],
  "visible": [
    "benchmark",
    "record_handle",
    "title",
    "question",
    "instructions",
    "evidence",
    "label_options",
    "llm_proposal"
  ]
}
```

Expected SHA-256:

```text
337c9be7e6feff9d472628ba22904b6389803e6ca1545d88b3066b758dffb17e
```

## `queue_hash` projection

```json
[
  {
    "ordinal": 0,
    "task_id": "pilot-v2-t4-001",
    "record_handle": "pilot-v2-record-001",
    "record_hash": "83e6580f823ebbb3b22d20ae4a5328c4c3923b84e9f8fd1754b7f87855ce6cf3"
  }
]
```

Expected SHA-256:

```text
e0019b18f30868bd345b0bd1f04f38ed70adcc93a56c3ed0cf33f3c1bc51b7bd
```

## 재현 명령

이 명령은 fixture에서 record projection을 만들고, 위에 고정한 mask/queue projection을 같은 Worker 함수로 hash한 뒤 세 값을 모두 대조합니다.

```bash
AAMD_NODE=/data1/users/ljk98/Amrs-runtime/tools/node-v22.23.5-linux-x64/bin/node

"$AAMD_NODE" -e 'import("./worker/index.js").then(async ({__test})=>{const {readFile}=await import("node:fs/promises");const b=JSON.parse(await readFile("fixtures/pilot-bundle.synthetic.json","utf8"));const t=b.tasks[0];const record={benchmark:t.benchmark,record_handle:t.record_handle,title:t.title,question:t.question,instructions:t.instructions,evidence:t.evidence,label_options:t.label_options};const mask={schema_version:2,strategy:"abstract-evidence-plus-frozen-llm-proposal",forbidden:["raw_payload","raw_prompt","attack_text","harmful_request","target_response","outcome","ground_truth","system_prompt"],visible:["benchmark","record_handle","title","question","instructions","evidence","label_options","llm_proposal"]};const queue=[{ordinal:0,task_id:t.task_id,record_handle:t.record_handle,record_hash:t.record_hash}];const got={record_hash:await __test.sha256Hex(record),visibility_mask_hash:await __test.sha256Hex(mask),queue_hash:await __test.sha256Hex(queue)};for(const [key,value] of Object.entries(got)){const expected=key==="record_hash"?t.record_hash:b[key];if(value!==expected)throw new Error(`${key}: expected ${expected}, got ${value}`)}console.log("pilot fixture hashes: valid")})'
```

이 hash recipe는 synthetic fixture만 설명합니다. 실제 claim-bearing bundle은 별도의 사전등록된 mask specification, source commitment, queue construction code와 외부 timestamp를 가져야 합니다.

## RCAT-7 V3 synthetic fixture versioning

`pilot-bundle.taxonomy-v3.synthetic.json`은 `aamd-llm-first-taxonomy-review-v3`의 다중 축
UI·검증·event chain을 시험합니다. 실제 32B 추론 결과가 아니라 사람이 만든 synthetic
smoke fixture이며 논문 표본이나 성능 결과가 아닙니다. Fixture의 taxonomy ID, semantic
version, canonical hash와 축 계약은 반드시 같은 revision을 가리켜야 합니다. 아래 hash는
V1.1 이전 synthetic fixture를 재현하기 위한 **legacy V1.0 고정값**이며 V1.1 bundle이나
claim-bearing import에 재사용하지 않습니다.

고정 계약:

- bundle `schema_version`: `2`
- export `schema_version`: `3`
- taxonomy: `aamd-rcat-7-v1` / `1.0.0`
- taxonomy canonical SHA-256: `9c739c3431de269b116d5d4c142df513fa64ff431259ba3f4c0039bf6316a489`
- `record_hash`: `52fc826c192dd5d7da1ececcc2ced6802e35ad344ec56ae3644b11fa505cfcae`
- `visibility_mask_hash`: `f99e751a0f60120608b2fa4b3e78bb1750a2b3afc243f2efd0302e465e18df15`
- `queue_hash`: `1d19087071fd7ebdbf0aa27199aed6d7b4c49820c8257e63075c9edf05085f51`

Legacy V1.0 record projection은 다음 키를 사용했습니다.

```text
benchmark, record_handle, title, question, instructions, evidence,
taxonomy_id, taxonomy_version, taxonomy_hash
```

Legacy V1.0 visibility mask는 `schema_version: 3`, strategy `abstract-evidence-plus-frozen-taxonomy-proposal`이며 visible 목록에 위 task projection과 `llm_proposal`을 뒀습니다. `attack_method`를 포함해 raw payload, target response, outcome, ground truth, system prompt를 숨겼습니다. Queue projection은 ordered `{ordinal, task_id, record_handle, record_hash}` 배열입니다.

이 값은 과거 재현 메모이며 현재 fixture와 테스트는 아래 V1.1 계약만 검증합니다.

```bash
"$AAMD_NODE" --test \
  tests/taxonomy-v3-fixture.test.mjs \
  tests/taxonomy-v3-workflow.integration.test.mjs
```

## RCAT-7 V1.1 synthetic fixture contract

현재 V1.1 fixture는 새 taxonomy canonical hash와 함께 전체 구조를 다시 생성했으며 위
V1.0 hash를 부분적으로 가져오지 않았습니다. 동결값은 다음과 같습니다.

- taxonomy: `aamd-rcat-7-v1.1` / `1.1.0`
- taxonomy canonical SHA-256: `2f8512333c90888aa640e8432ec262cdd452adbae3d1e8df5c96c5654a5c816c`
- `record_hash`: `ef2940d656f038bd345ed6942c2b79e56761ef051c27895a08129c3ace5784ef`
- `locked_axes_hash`: `0bb14e65e3bbfb58762d5e98f9d9668c1fc78f8593162bd16e328ad51b976c3c`
- `visibility_mask_hash`: `dbc3df1c573217c17873853aa8d4df45e6e63d1c5cd8c777272cbadf738c5892`
- `queue_hash`: `8ecb617143ab6a1669e389ba53c425411802c82f8fc70acfbd4978bd516c671f`

현재 record projection은 아래 키를 정확히 사용합니다.

```text
benchmark, record_handle, title, question, instructions, evidence,
taxonomy_id, taxonomy_version, taxonomy_hash, locked_axes, locked_axes_hash
```

현재 visibility mask의 visible 목록도 `locked_axes`, `locked_axes_hash`, `llm_proposal`을
명시적으로 포함합니다. 따라서 잠금축 값이 바뀌면 record hash와 lock hash를 모두 새로
계산해야 하며, proposal의 `locked_axes_hash`도 같은 값에 결박되어야 합니다.

### Human-reviewed proposal

LLM proposal과 primary/secondary/adjudicated judgment가 다루는 축은 정확히 네 개입니다.

1. `adaptation_mechanism`: 7개 RCAT-7 leaf 중 하나 또는 sentinel
2. `consumed_response_signal`: successor가 실제 소비한 최소 응답 단서 하나
3. `search_action`: global switch, local parameter change, current-operation continue,
   material-change 없는 repeat 중 하나 또는 sentinel
4. `semantic_linkage`: `RCAT7.LINKAGE.EXPLICIT_CONTENT_DEPENDENCE`,
   `RCAT7.LINKAGE.IMPLICIT_OPERATION_DEPENDENCE` 또는 sentinel

`mapping_status=mapped`이면 non-sentinel mechanism과 positive semantic linkage가 둘 다
필수입니다. 모든 positive reviewed label은 confidence, direct evidence handle과 rationale을
가집니다. `benign_confound`는 selected mechanism 아래에 등록된 code만 사용할 수 있고,
plausibility, direct evidence handle과 rationale이 필수입니다.

### Machine-locked task state

다음 네 축은 fixture task를 만들 때 event-ledger/receipt parser output으로 고정하며 proposal과
human judgment에는 넣지 않습니다.

- `memory_source_scope`
- `memory_operation`
- `evidence_provenance`
- `dialogue_horizon`

Fixture는 reviewer 또는 adjudicator가 locked value를 제출해 덮어쓰려는 요청이 거부되는지,
receipt 누락/손상이 locked `uncertain`으로 남는지, 그리고 이견이 원값과 원 receipt hash를
보존한 append-only `provenance_dispute` event로 export되는지를 시험해야 합니다.

Claim-core positive smoke row는 다음 predicate를 만족해야 합니다.

```text
mapping_status == mapped
AND evidence_provenance == RCAT7.PROVENANCE.DIRECT_RESPONSE_TO_SUCCESSOR_RECEIPT
```

단, 이 synthetic row는 predicate와 validator를 시험할 뿐 실제 causal evidence나 annotation
quality를 제공하지 않습니다. V1.1 fixture와 테스트는 다음을 고정합니다.

- taxonomy ID / semantic version / canonical SHA-256
- record, visibility-mask, queue SHA-256
- locked-axis source receipt projection과 hash
- proposal이 네 reviewed 축만 갖는다는 coverage assertion
- memory source/operation receipt invariant와 provenance-dispute negative test
