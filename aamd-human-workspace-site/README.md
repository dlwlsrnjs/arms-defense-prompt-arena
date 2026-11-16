# AAMD Human Annotation Workspace

적응형 공격 메모리를 방어에 유용한 추상 규칙으로 선별하기 위한 **비공개 LLM-first 사람 검수 워크스페이스**입니다. 새 수집 프로토콜 `aamd-llm-first-human-review-v2`는 사전 계산·동결된 LLM 제안을 먼저 보여주고, 사람의 `accept`/`edit`/`reject`/`abstain` 검수, 같은 제안을 보는 독립 2차 검수, 제3자 조정(adjudication)을 append-only 원장에 기록합니다.

> **현재 연구 상태:** private workflow prototype / pilot. 이 저장소의 UI와 원장은 수집 절차를 통제하지만, 그 자체로 논문용 표본을 만들지는 않습니다. IRB 승인 또는 면제, 참여자 동의·보존 정책, 동결된 G2 입력 bundle, 사전등록된 분석 계획, 독립 원장 checkpoint를 모두 갖추기 전 기록은 claim-bearing denominator에 포함하지 마십시오.

## 가장 중요한 운영 원칙: 실험 중 AICA를 사용하지 않는다

```text
실험 전 (offline)                 실험 중                         실험 후
-------------------------       -----------------------------   --------------------------
기록 추상화·마스킹               Private ChatGPT Site           관리자 export
LLM proposal 사전 계산     -->   Sites Worker + D1 only    -->  event/receipt 검증
bundle/hash 동결·2인 승인         사람 판정과 단계 잠금            외부 checkpoint·분석
```

- 실험 런타임에는 AICA, vLLM, GPU, 모델 API, 연구실 서버가 필요하지 않습니다.
- Worker에는 외부 서버로 나가는 `fetch` 경로가 없습니다. 브라우저는 동일 origin의 `/api/*`만 호출합니다.
- task와 LLM proposal은 **실험 전에** payload-free bundle로 계산·고정한 뒤 D1에 import합니다.
- v2에서는 primary와 secondary가 각자 검수를 시작할 때 동일한 frozen proposal을 받습니다. secondary에게 primary vote는 전달하지 않습니다.
- 실험 후 export는 event hash chain, 개별 HMAC-SHA256 receipt, export hash와 top-level export signature를 보존해야 합니다.
- 따라서 AICA가 중단되거나 완전히 격리되어 있어도 이미 승인된 실험은 계속 진행할 수 있습니다.

English summary: this is an AICA-independent, private human-review runtime. Compute and freeze masked tasks and LLM proposals before the study; run the study on Sites Worker + D1 only; export the hash-linked, receipt-signed ledger afterward.

## 수집 흐름

1. offline proposer가 model revision, prompt/template, decoding, seed, codebook과 함께 proposal을 계산하고 bundle에 동결합니다.
2. `primary`가 추상 증거와 frozen proposal을 함께 보고 `accept`, `edit`, `reject`, `abstain` 중 하나와 최종 judgment를 제출합니다.
3. 다른 사람인 `secondary`가 **같은 proposal**과 같은 추상 증거를 보되 primary vote를 받지 않고 독립 검수합니다.
4. primary·secondary와 다른 `adjudicator`가 proposal과 두 vote를 보고 최종 조정합니다.

v2의 저장 단계는 `final → secondary → adjudicate`이며 expected version은 각각 `0 → 1 → 2`입니다. `final`은 v2에서 primary human review를 뜻합니다. 이미 잠긴 단계는 수정·삭제할 수 없습니다. 과거 `aamd-human-protocol-v1` bundle은 `initial → reveal → final → secondary → adjudicate` 의미를 그대로 유지하며 새 기록으로 재해석하지 않습니다.

T4 task는 다음 네 필드를 정확히 기록합니다.

- `defense_invariant`: 일반화 가능한 방어 불변식
- `benign_exception`: 정상 대화를 과잉 차단하지 않기 위한 예외
- `predicted_readaptation`: 방어 노출 뒤 예상되는 재적응
- `evaluation_probe`: 불변식과 예외를 함께 시험할 평가 항목

## 역할과 분리 규칙

| 역할 | 권한 | 분리 규칙 |
| --- | --- | --- |
| `admin` | role 부여, bundle import/approve, export | reviewer 역할과 결합하지 않음 |
| `primary` | frozen proposal을 검토해 final review 잠금 | 같은 task의 secondary/adjudicator가 될 수 없음 |
| `secondary` | 같은 frozen proposal을 보되 primary vote 없이 독립 검수 | primary와 다른 사용자 |
| `adjudicator` | 두 vote 공개 후 조정 | primary·secondary와 다른 사용자 |

- bundle 업로더와 승인자는 반드시 서로 다른 admin이어야 합니다.
- `admin`은 단독 역할입니다. 한 사용자에게 admin과 reviewer 역할을 함께 부여할 수 없습니다.
- 한 번이라도 admin이었던 identity는 `admin_tainted=1`로 영구 표시되며 이후 reviewer로 전환할 수 없습니다. 이 제약은 Worker와 D1 trigger 양쪽에서 강제됩니다.
- 첫 assignment 이후 그 사용자의 reviewer role은 동결됩니다.
- 최소 운영 인원은 admin 2명, reviewer 3명입니다. 연구 설계에 따라 reviewer를 더 두는 것이 좋습니다.

## 최초 설정과 사람 초대

### 1. Site를 private로 유지

Sites access mode를 `custom` 또는 그보다 엄격한 비공개 설정으로 유지하고, 참여자만 초대합니다. GitHub Pages 데모는 설명용일 뿐 실제 사람 평가나 claim-bearing 기록에 사용하지 않습니다.

### 2. D1과 비밀 환경변수 설정

`.openai/hosting.json`의 D1 binding은 `DB`입니다. 앞의 세 값은 secret으로 설정하고, 마지막 claim gate는 아래 조건을 만족하기 전까지 미설정 또는 false로 둡니다.

| 변수 | 용도 |
| --- | --- |
| `AAMD_RECEIPT_HMAC_KEY` | identity pseudonym, stage receipt, export signature용 32자 이상 비밀값 |
| `AAMD_BOOTSTRAP_ADMIN_IDS` | 쉼표로 구분한 초기 admin Sites account ID |
| `AAMD_BOOTSTRAP_ADMIN_EMAILS` | 쉼표로 구분한 초기 admin 이메일 |
| `AAMD_CLAIM_COLLECTION_ENABLED` | preregistered claim gate를 통과한 경우에만 정확히 `true`; 기본/현재는 pilot-only |

논문용 수집 도중 `AAMD_RECEIPT_HMAC_KEY`를 바꾸면 기존 receipt 검증이 끊깁니다. 연구별 key를 안전하게 보관하고, 소스·bundle·export에 넣지 마십시오.

### 3. 두 admin을 먼저 등록

두 admin을 bootstrap 환경변수에 미리 넣는 방법이 가장 단순합니다. 각 admin이 Site를 한 번 방문하면 trusted Sites identity header를 기반으로 계정이 D1에 등록되고 admin role이 생깁니다. 첫 admin이 bundle을 import하고 두 번째 admin이 승인합니다.

### 4. reviewer 등록과 role 부여

1. 참여자를 private Site access list에 초대합니다.
2. 참여자가 Site를 한 번 방문해 자신의 등록을 만듭니다.
3. 참여자는 Dashboard의 identity 표시 또는 `GET /api/me`의 `user.account_id`에서 자신의 account ID를 확인해 운영자에게 전달합니다.
4. admin은 **Administration → Role assignment**에서 해당 ID와 `primary`, `secondary`, `adjudicator` 중 역할을 부여합니다.
5. assignment를 시작하기 전에 role과 연구 cohort를 다시 확인합니다. 첫 assignment 뒤에는 role 변경이 거부됩니다.

이메일 텍스트를 role API의 `auth_user_id` 자리에 넣지 마십시오. role 부여는 trusted account ID를 정확히 사용합니다.

## Bundle 준비와 2인 승인

Bundle은 실험 전에 만들어야 하며, 원문 공격 payload나 target response를 담으면 안 됩니다. 허용되는 것은 blinded handle, hash, 추상 evidence, codebook, 사전 계산 proposal입니다.

운영 순서:

1. AICA 또는 별도 offline 환경에서 후보 기록을 추상화하고 proposal을 계산합니다.
2. source record, visibility mask, queue 순서를 동결하고 SHA-256 hash를 계산합니다.
3. bundle을 로컬에서 contract validator로 검증합니다.
4. admin A가 Administration에 JSON을 붙여 넣고 **검증·격리**합니다.
5. import 응답의 `bundle_hash`, `task_count`, bundle ID를 외부 체크리스트와 대조합니다.
6. admin B가 같은 bundle ID를 **별도 관리자 승인**합니다.
7. 승인 이후에만 reviewer assignment가 가능합니다.

현재 UI의 reviewer queue는 bundle ID를 직접 선택하지 않고 가장 먼저 승인된 bundle을 기본값으로 사용합니다. 한 cohort/deployment에는 하나의 active approved bundle만 두고, 독립 연구나 다음 cohort는 별도 private Site/D1로 분리하십시오.

### Top-level schema

```json
{
  "schema_version": 1,
  "bundle_id": "frozen-unique-id",
  "mode": "pilot_import",
  "claim_bearing": false,
  "protocol_version": "aamd-llm-first-human-review-v2",
  "codebook_version": "codebook-v2",
  "visibility_mask_hash": "64-char lowercase sha256",
  "queue_hash": "64-char lowercase sha256",
  "tasks": []
}
```

- `mode`는 `pilot_import` 또는 `claim_bearing_candidate`입니다. 후자는 모든 연구 gate를 통과한 뒤 `AAMD_CLAIM_COLLECTION_ENABLED=true`를 명시한 배포에서만 import됩니다.
- `pilot_import`는 반드시 `claim_bearing: false`, `claim_bearing_candidate`는 반드시 `true`입니다.
- task는 1–500개이고 benchmark는 `T1`–`T4`, split은 항상 `blinded`입니다.
- bundle/task object는 allowlist 기반이므로 문서에 없는 필드를 넣으면 import가 실패합니다.

### Task와 proposal schema

```json
{
  "task_id": "unique-task-id",
  "benchmark": "T4",
  "record_handle": "blinded-record-id",
  "record_hash": "64-char lowercase sha256",
  "split": "blinded",
  "claim_bearing": false,
  "title": "visible title",
  "question": "visible review question",
  "instructions": "visible protocol instruction",
  "evidence": [
    {"handle": "ev-1", "label": "visible label", "value": "abstract evidence"}
  ],
  "label_options": [
    {"value": "label-a", "label": "Label A", "help": "codebook help"},
    {"value": "label-b", "label": "Label B", "help": "codebook help"}
  ],
  "llm_proposal": {
    "proposal_id": "offline-proposal-id",
    "version": "frozen-model-template-version",
    "label": "label-a",
    "confidence": 75,
    "evidence_handles": ["ev-1"],
    "rationale": "abstract rationale",
    "affordance": {
      "defense_invariant": "...",
      "benign_exception": "...",
      "predicted_readaptation": "...",
      "evaluation_probe": "..."
    }
  }
}
```

`affordance`는 T4에만 필요하며 T1–T3에는 넣으면 안 됩니다. evidence handle과 label value는 task 내부에서 유일해야 하고 proposal은 해당 task의 handle/label만 참조할 수 있습니다.

다음 이름과 의미의 원문·누설 필드는 재귀적으로 거부됩니다: raw payload/prompt, attack text/method, harmful request, target response, 실제 outcome/ground truth/split, judge rationale, system prompt, secret/token. 단어를 다른 key로 바꾸어 우회하지 말고, 실제 연구 마스킹 사양에서도 같은 정보 범주를 제거하십시오.

## 안전한 synthetic pilot fixture

[`fixtures/pilot-bundle.synthetic.json`](fixtures/pilot-bundle.synthetic.json)은 다음 성질을 가진 비논문용 smoke-test bundle입니다.

- `mode: pilot_import`, `claim_bearing: false`
- 실제 공격 원문·실제 모델 응답·숨은 label이 없는 합성 추상 증거
- 현재 `validateBundle` contract를 통과하는 1개 T4 task
- 연구 결과나 성능 예시로 사용할 수 없음

fixture hash는 Worker의 key-sorted canonical JSON과 SHA-256으로 계산했습니다. 정확한 projection JSON과 재현 명령은 [`fixtures/README.md`](fixtures/README.md)에 고정했습니다.

- `record_hash`: `benchmark`, `record_handle`, `title`, `question`, `instructions`, `evidence`, `label_options`로 구성한 masked-record projection
- `visibility_mask_hash`: 문서화된 `abstract-evidence-plus-frozen-llm-proposal` mask 사양 projection
- `queue_hash`: 순서가 있는 `{ordinal, task_id, record_handle, record_hash}` 배열

fixture는 UI와 단계 전이를 시험하기 위한 것뿐입니다. 실제 G2 bundle의 provenance나 동결 증거를 대신하지 않습니다.

## Reviewer 운영 절차

### Primary

1. My queue에서 `primary`를 선택하고 다음 과제를 배정합니다.
   승인된 bundle이 둘 이상이면 bundle selector에서 정확한 v2 bundle ID와 protocol ID를 먼저 확인합니다.
2. abstract evidence, codebook, frozen LLM proposal을 함께 대조합니다.
3. 제안이 그대로 타당하면 `accept`, 수정해 사용할 수 있으면 `edit`, 다른 비기권 판정으로 대체해야 하면 `reject`, 근거가 부족하면 `abstain`을 선택합니다.
4. T4이면 네 affordance 필드를 모두 검토하고 필요한 부분을 수정합니다.
5. final review를 잠근 뒤 receipt를 확인합니다. `accept`는 proposal-derived judgment가 정확히 동일해야 하고, `edit`/`reject`는 proposal과 달라야 합니다.

v2 decision code는 정확히 `accept`, `edit`, `reject`, `abstain`입니다.

### Secondary

`secondary` queue에는 primary final이 잠긴 task만 나타납니다. secondary는 primary와 동일한 frozen proposal을 보지만 서버 응답에서 primary vote는 제외됩니다. `accept`/`edit`/`reject`/`abstain`으로 독립 검수를 잠근 다음에는 수정할 수 없습니다.

### Adjudicator

`adjudicator` queue에는 secondary까지 잠긴 task만 나타납니다. primary final과 secondary vote를 비교해 `agreement`, `resolved`, `pending`, `disagreement`, `escalated` 중 resolution과 최종 judgment를 기록합니다.

## Admin export와 검증

Administration에서 bundle ID를 넣어 export합니다. export에는 다음이 포함됩니다.

- frozen bundle metadata와 approval hash
- 공개 task, proposal hash, 공개 여부에 따른 proposal 본문
- pseudonymous assignment records
- stage event payload/hash chain
- HMAC-SHA256 server receipts
- `export_hash`, `signature_algorithm`, top-level `export_signature`

v2의 `proposal_release_status`는 실제 브라우저 열람을 주장하지 않습니다. 미승인 bundle은 `sealed_unapproved`, 승인됐지만 미배정이면 `approved_not_assigned`, reviewer assignment가 생겨 role-authorized task view에서 proposal을 받을 수 있으면 `available_to_assigned_reviewers_before_human_review`로 기록합니다. 현재 원장은 별도 page-view event를 수집하지 않으므로 이를 “reviewer가 실제로 읽었다”는 증거로 해석하지 마십시오.

원본 `auth_user_id`, HMAC key, 미공개 proposal, 원문 payload는 export하면 안 됩니다. 다운로드 직후 별도 보존소에 read-only copy를 만들고, 외부 timestamp/Merkle checkpoint에 export hash를 고정하십시오. HMAC은 같은 비밀키를 가진 서버 운영자가 검증하는 대칭키 증거이므로, 공개 검증 가능한 전자서명과 같다고 주장하지 마십시오.

검증 시 `export_hash`/`signature_algorithm`/`export_signature`를 제거한 canonical export의 SHA-256이 `export_hash`와 같은지 먼저 확인합니다. 그다음 `{export_hash, bundle_id, generated_at}`의 canonical JSON에 대한 HMAC-SHA256이 `export_signature`와 같은지 연구 보관 key로 확인합니다.

## API 계약

모든 `/api/*`는 private Sites authentication을 요구합니다. 모든 POST는 동일 origin의 `Origin`, `Content-Type: application/json`을 요구합니다. stage POST는 8–128자의 `Idempotency-Key`도 요구합니다.

| Method | Endpoint | Role | 설명 |
| --- | --- | --- | --- |
| GET | `/api/me` | authenticated | identity, own account ID, roles, runtime dependency |
| POST | `/api/bootstrap` | authenticated | 최초 방문 등록 및 bootstrap admin 적용 |
| GET | `/api/dashboard` | authenticated | bundle 상태와 내 assignment 요약 |
| POST | `/api/admin/roles` | admin | 등록된 account ID에 role 부여 |
| POST | `/api/admin/import` | admin | 최대 1 MiB bundle 검증·격리 |
| POST | `/api/admin/approve` | 다른 admin | uploader와 다른 사람이 immutable bundle 승인 |
| GET | `/api/admin/export?bundle_id=...` | admin | hash-chain export 생성 |
| POST | `/api/tasks` | reviewer | role과 optional bundle ID로 다음 task 배정 |
| GET | `/api/tasks?role=...` | reviewer | 내 queue 목록 |
| GET | `/api/tasks/{id}?role=...` | assigned reviewer | 역할별로 마스킹된 task view |
| POST | `/api/tasks/{id}/initial` | primary | legacy v1 blind initial 잠금; v2에서는 거부 |
| POST | `/api/tasks/{id}/reveal` | primary | legacy v1 proposal 공개; v2에서는 이미 보이므로 거부 |
| POST | `/api/tasks/{id}/final` | primary | v2 LLM-first 사람 검수 잠금 (`expected_version: 0`) |
| POST | `/api/tasks/{id}/secondary` | secondary | 같은 proposal에 대한 독립 검수 잠금 (`expected_version: 1`) |
| POST | `/api/tasks/{id}/adjudicate` | adjudicator | 최종 조정 잠금 |

## 로컬 검증

이 저장소의 시스템 Node가 오래된 환경에서는 project runtime에 설치한 Node 22를 명시적으로 사용합니다.

```bash
cd /home/ljk98/Amrs/github/arms-defense-prompt-arena/aamd-human-workspace-site
AAMD_NODE=/data1/users/ljk98/Amrs-runtime/tools/node-v22.23.5-linux-x64/bin/node

"$AAMD_NODE" --check worker/index.js
"$AAMD_NODE" scripts/validate-claim-contract.mjs
"$AAMD_NODE" --test tests/*.test.mjs
"$AAMD_NODE" -e 'import("./worker/index.js").then(async ({__test})=>{const {readFile}=await import("node:fs/promises");const value=JSON.parse(await readFile("fixtures/pilot-bundle.synthetic.json","utf8"));__test.validateBundle(value);console.log("pilot fixture: valid")})'
```

## Build와 private Sites 배포

용량 증가 artifact는 root filesystem에 만들지 않습니다. Sites source를 `/data1/users/ljk98/Amrs-runtime/site-builds/aamd-human-workspace/` 아래의 run-scoped checkout으로 복사한 다음 그 checkout에서 build합니다.

```bash
cd /data1/users/ljk98/Amrs-runtime/site-builds/aamd-human-workspace/<run-checkout>
AAMD_NODE=/data1/users/ljk98/Amrs-runtime/tools/node-v22.23.5-linux-x64/bin/node

bash scripts/build.sh
"$AAMD_NODE" scripts/validate-artifact.mjs
"$AAMD_NODE" scripts/validate-claim-contract.mjs
"$AAMD_NODE" --test tests/*.test.mjs
```

공식 Sites source workflow로 checkout/commit을 만들고 `dist/`와 `drizzle/` migration을 같은 version으로 저장합니다. 그다음 `save_version_and_deploy_private` 경로로 배포하고 다음을 확인합니다.

1. project ID가 `.openai/hosting.json`과 일치한다.
2. access mode가 `custom`/private이고 공개 전환되지 않았다.
3. D1 binding 이름이 `DB`이다.
4. HMAC key와 bootstrap 값 세 개가 secret으로 존재하고 claim flag는 의도대로 false/미설정 상태이다.
5. `/api/me`와 Dashboard가 `Sites Worker + D1 only`를 보고한다.
6. synthetic v2 pilot import → 다른 admin 승인 → primary/secondary/adjudicator 단계 → export가 완주한다.
7. 실험 중 AICA endpoint와 GPU process가 없어도 같은 smoke test가 통과한다.

## 논문 claim으로 전환하기 전 필수 gate

- [ ] IRB 승인/면제와 참여자 동의 문구가 연구 기관 기준으로 확정됨
- [ ] 철회, 보존 기간, 접근 통제, 보상, incident 대응 정책이 확정됨
- [ ] G2 입력 계약과 payload-free visibility mask가 동결됨
- [ ] source cohort, exclusion, queue order, protocol, codebook, proposal model/template/decoding provenance가 사전등록됨
- [ ] 모든 hash와 bundle artifact가 연구 시작 전에 외부 저장소에 고정됨
- [ ] 독립 admin 2명과 서로 다른 primary/secondary/adjudicator 배정이 준비됨
- [ ] primary와 secondary에게 같은 frozen proposal이 사람 검수 전에 전달되고, secondary에게 primary vote가 숨겨지는 integration test가 통과함
- [ ] proposer model revision, prompt/template, decoding, seed, codebook hash가 bundle 생성 전에 동결됨
- [ ] 정확도 또는 anchoring 효과를 주장한다면 별도 proposal-blind expert reference subset과 분석 계획이 사전등록됨
- [ ] D1 밖의 timestamp/Merkle checkpoint가 운영됨
- [ ] 분석 code와 denominator가 사전 동결됨
- [ ] pilot bundle/event가 claim-bearing export에서 배제됨

이 gate를 통과하기 전에는 시스템을 “논문용 데이터셋 수집 완료”나 “tamper-proof ledger”로 표현하지 마십시오. 현재 구현의 정확한 표현은 **AICA-independent LLM-first human-review prototype with an append-only application ledger**입니다.

이 프로토콜은 일반적인 LLM-assisted annotation 절차이며, 사람 검수가 LLM 오류나 자동화 편향을 제거한다고 보장하지 않습니다. 두 reviewer가 같은 proposal을 보므로 오류가 상관될 수 있고, 높은 agreement/acceptance도 accuracy나 anchoring 감소의 증거가 아닙니다. proposal-blind expert reference subset이 없다면 counterfactual human label이나 anchoring의 인과 효과를 주장하지 않습니다.

현재 Worker에는 참여자 동의서 제시·서명·철회 기록 기능이 없습니다. `AAMD_CLAIM_COLLECTION_ENABLED=true`는 기술적 import gate일 뿐 IRB나 동의를 증명하지 않습니다. claim-bearing 수집 전에는 승인된 외부 동의 절차를 연동하거나 별도의 검증 가능한 consent stage를 구현해야 합니다.
