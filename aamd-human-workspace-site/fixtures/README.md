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
