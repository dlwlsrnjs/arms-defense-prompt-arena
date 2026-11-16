# AAMD Human Annotation Workspace

> **Legacy public-demo guide.** 아래 정적 GitHub Pages 절차는 v1 blind-first simulator를 설명하며 claim-bearing 수집에 사용하지 않습니다. 현재 비공개 수집 워크스페이스와 신규 protocol은 [`AAMD_LLM_FIRST_HUMAN_REVIEW_PROTOCOL_V2.md`](AAMD_LLM_FIRST_HUMAN_REVIEW_PROTOCOL_V2.md)를 따릅니다.

The AAMD workspace is a paper-data review surface for payload-free adaptive-attack-memory records. It is separate from the exploratory **Memory Evidence Lab**: the lab helps inspect pilot artifacts, while AAMD records a fixed assignment protocol with immutable stage events.

Open the site and select **06 · AAMD Workspace** in the left menu, or use the workspace hash route `#view-aamd`.

## What the public site can and cannot do

The workspace has three explicit bundle modes.

| Mode | Executable on the public static site | Claim-bearing |
|---|---:|---:|
| `excluded_demo` | Yes | No |
| `pilot_import` | Yes | No |
| `claim_bearing_candidate` | No, unless a controlled-delivery adapter and matching capability receipt are supplied by a research server | Candidate only |

The built-in bundle is safe abstract metadata and is always marked **EXCLUDED DEMO · NOT CLAIM-BEARING**. A pilot import is also excluded from paper denominators.

Client-side hiding is only a user-interface phase gate. If a proposal is embedded in browser-delivered source, a reviewer can inspect it before the initial lock. Therefore claim-bearing collection must omit embedded proposals and use a controlled server that releases a versioned proposal only after receiving the initial-event hash and visibility-mask hash. This repository does not ship that server or its capability. A local export remains non-authoritative until server-side signed ingestion, duplicate checks, schema validation, and append-only ledger acceptance.

## Fixed review sequence

1. Enter a pseudonym and start a local session. The bundle hash, codebook hash, visibility-mask hash, queue hash, reviewer, and assignment order are fixed.
2. Complete assignments in manifest order. A later task cannot be selected or locked before every earlier task has a primary final judgment.
3. Make the human initial label from the displayed evidence handles. Record confidence, rationale, or an explicit abstention. T4 also requires a defense invariant, benign exception, evaluation probe, and predicted attacker re-adaptation.
4. Lock the initial event. Only then can the versioned LLM proposal be revealed.
5. Record `accept`, `retain_human`, `edit_after_proposal`, `reject_proposal`, or `abstain_after_proposal`. The initial event remains immutable.
6. Start an independent second vote. Its pseudonym must differ from the primary reviewer, and the primary/proposal/final panels are hidden during the vote. A non-abstaining T4 vote records all four affordance fields independently.
7. Use a third pseudonym for adjudication. `agreement` must match both non-null votes; `resolved` requires a codebook label and, for T4, all four resolved affordance fields; `pending`, `disagreement`, and `escalated` are explicit no-gold states.

The four task views do not change manifest order:

- **T1 — Trace verification:** whether receipts attest the claimed transition.
- **T2 — Retrieval:** which payload-free memory abstraction matches the current cue.
- **T3 — Adaptation prediction:** which registered operation category is likely next.
- **T4 — Affordance generation:** a defense invariant, utility-preserving exception, falsifiable probe, and predicted re-adaptation.

## Bundle integrity contract

Imports are at most 1 MiB and use schema version 1. The browser rejects forbidden raw-payload field names, unknown benchmark IDs, duplicate task/evidence/label identifiers, invalid label references, and unsafe mode combinations. It recomputes four hashes before accepting a bundle:

- `record_hash` from `canonical_public_task_v1` for every task;
- `codebook_hash` from `canonical_benchmark_label_options_v1`;
- `queue_hash` from ordered assignment identities;
- `visibility_mask_hash` from `canonical_visibility_mask_v1`.

For claim-bearing candidates, every visible `split` value must be exactly `blinded`; the actual split name must not be delivered to the browser. The static validator proves only that the checked-in demo fixture is payload-free. Imported evidence text is untrusted and must pass the controlled ingestion validator before research use.

## Exports

**Annotation JSON is the verification artifact.** It contains complete immutable stage payloads, lock/reveal timestamps, provenance links, visibility-mask links, and event hashes. Export performs an event-chain verification before download. The same in-browser state serializes to the same UTF-8 bytes because object keys are recursively sorted and task/event arrays retain manifest order.

**Annotation CSV is a lossy analysis projection.** It is deterministic but intentionally omits complete stage payloads and cannot independently recompute every event hash. Preserve the JSON beside any CSV used for analysis. Cells that could be interpreted as spreadsheet formulas are apostrophe-prefixed before quoting.

All draft data is stored in browser `localStorage`. Export before clearing a session. Do not enter names, secrets, raw attack prompts, raw target responses, or judge rationales.

## Validation

Run from the repository root:

```bash
node --check dist/aamd-workspace.js
node scripts/validate-aamd-workspace.cjs
node scripts/validate-site.cjs
```

The AAMD test checks bundle rejection, canonical hash recomputation, blind-first reveal gating, label membership, and deterministic JSON/CSV helpers. The site validator checks all seven dashboard views, required AAMD controls, the safe demo boundary, checked-in fixture hashes, and public-file secret patterns.

Authoritative task-bundle and annotation-export JSON Schemas remain **G2 pending**. The browser validator is a fail-closed usability guard, not the authoritative dataset-ingestion validator, and must not be cited as evidence that G2 passed.
