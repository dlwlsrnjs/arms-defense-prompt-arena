# Heterogeneous Adaptive-Attack Preregistration v1

## Status at a glance

This bundle is a **registration candidate, not a frozen experiment and not an
efficacy result**. It defines the evidence that must exist before the first
main-data model call. The project uses a clean-room, multi-method adaptive
attack harness; it does not claim to reproduce the unpublished implementation
of ARMS.

| Item | Current state | Claim boundary |
|---|---|---|
| Attack methods | Five observed upstream revision candidates | Not frozen until G0 |
| Adapter parity | Not run | All methods blocked until G1 |
| Behavior sources | HarmBench, AdvBench, SALAD-Bench revision/license candidates observed | Local full-hash and dataset-terms audit unresolved; G0 blocked |
| Behavior splits | Algorithm and proportions registered | Private manifests/power cap unresolved; G2 blocked |
| Model targets | Qwen2.5-VL 3B/7B/32B revision candidates | Attestation required at G0 |
| Primary feedback | Target response only | Judge feedback is a separate diagnostic |
| Main experiment | Not started | No attack/defense efficacy claim is allowed |

The machine-readable sources of truth are:

- `configs/adaptive_attack_universe_v1.json`
- `configs/behavior_registry_v1.json`
- `schemas/behavior-registry-v1.schema.json`
- `defense_arena/adaptive_attack_preregistration.py`
- `scripts/validate_adaptive_attack_preregistration.py`

The human–LLM data-construction claim, its current pilot boundary, and the
required blind-first/adjudication protocol are specified in
[`HUMAN_LLM_ATTACK_DYNAMICS_DATA_PROTOCOL_V1.md`](HUMAN_LLM_ATTACK_DYNAMICS_DATA_PROTOCOL_V1.md).
That document is methodological guidance until its config, schema, validator,
assignment manifest, and hashes pass G0; its presence does not freeze the
annotation protocol.

## Why this is the first priority

The research claim is not that one hand-picked attack memory helps against the
same examples. The intended claim is that a defense compiler can extract
compact, interpretable conversational invariants from a **predeclared,
heterogeneous adaptive-attack universe** and retain value when the attacker:

1. sees the defended target's responses;
2. changes its next operation based on those responses;
3. carries abstract memory across episodes; and
4. uses an attack method withheld from defense construction.

Without a frozen universe, unsuccessful episodes, rejected memory candidates,
or inconvenient methods could silently disappear. That would make apparent
generalization indistinguishable from selection bias. The preregistration
therefore makes failures, timeouts, fallbacks, method coverage, and data access
part of the primary research artifact rather than implementation details.

## Research questions

### RQ1 — Heterogeneous memory attribution

Does a payload-controlled heterogeneous adaptive-attack memory reduce sealed
live-adaptive attack success relative to equal-token controls built from:

- generic safety guidance;
- one attack method only;
- frequency counts without trajectories; and
- the same memory labels with transition links deliberately broken?

This asks whether cross-turn adaptation structure adds value, rather than
re-proving that model feedback can affect an adaptive attacker.

### RQ2 — Low-token safety–utility feasibility

Can typed attack trajectories be compiled into a short system prompt while
preserving benign utility when the attacker can react to each defended
response? The result is a joint safety, utility, and prompt-token claim; a
safety-only improvement is not sufficient.

### RQ3 — Unseen-method and target transfer

Does a prompt constructed from four methods transfer to the fifth method, and
does the conclusion hold across Qwen2.5-VL 3B, 7B, and 32B targets? Every method
is held out exactly once.

### RQ4 — Cost and explanation leakage

How do memory abstraction level, prompt token budget, and boundary-explanation
detail alter safe horizon, benign utility, and attacker re-adaptation cost?
Explanation is treated as an attack-visible channel, not as a free benefit.

## Registered attack universe

Five method families were chosen before outcome collection because together
they cover materially different adaptive operations:

| Method | Registered adaptation unit | Search topology | Observed candidate revision |
|---|---|---|---|
| PAIR | Revise from the target response | Parallel iterative paths | `6379ef705a0fc745530f7d895963510c021b496a` |
| TAP | Expand and prune using target-conditioned evidence | Tree search | `7bcdad30537c679d00699fac16052dc916c89a6d` |
| Crescendo (via PyRIT) | Continue a progressive dialogue using full history | Conversation trajectory | `986c890298b25811dbc35e83a2c2ee4e74dae6a6` |
| GPTFuzzer | Mutate and select templates using outcomes | Mutation search | `0c26cccc3b19cd5eed91d6cb6912431cf2501762` |
| AutoDAN-Turbo | Discover and reuse strategies over time | Strategy-library iteration | `389df844439888fc44ea7f5e8e95fd2b5c82ea64` |

The revisions above were observed with read-only `git ls-remote HEAD` on
2026-11-16 KST. They are evidence candidates, **not immutable pins**. The GitHub
license API reported MIT for each candidate. The public config records the
revision-addressed license URL and the observed Git-blob SHA prefix. G0 still
requires a local full-hash, license-text, setup, and dependency audit.

Two input URLs redirect to canonical repositories and both identities are
retained for provenance:

- `SaFoLab-WISC/AutoDAN-Turbo` → `SaFo-Lab/AutoDAN-Turbo`
- `sherdencooper/GPTFuzz` → `hubertyoo/GPTFuzz`

No method enters a claim-bearing run until its G1 adapter report reconciles
native settings, target/attacker call accounting, pruning/stopping semantics,
and fixed-seed structural output. If any one of the five methods cannot pass,
the experiment fails closed: amend the preregistration before running main
data, rather than quietly dropping the method.

## Feedback policy

The primary arm is **response-only**. After a target call the attacker may see
the target response, but not the judge score, judge rationale, policy label,
defense system prompt, or private behavior metadata. This matches the deployed
interaction channel the defense is meant to withstand.

A separate judge-feedback diagnostic may reveal a quantized score but never a
judge rationale. Its memory store is isolated from the primary arm, and its
results cannot support a primary claim. This separation prevents an unusually
informative research-time oracle from being mistaken for normal deployment.

## What counts as attack memory

The registered unit is a typed adaptation transition, not a successful prompt
example. At minimum it links:

1. method and target;
2. a salted behavior-cluster handle and episode handle;
3. predecessor strategy code;
4. target-response signal code;
5. next adaptation-operator code;
6. terminal or intermediate outcome code; and
7. retain, merge, reject, or quarantine decision.

This representation captures *where dialogue history changed the attacker's
next move*. Successful, unsuccessful, rejected, merged, quarantined, no-memory,
and fallback paths are all preserved. Public exports contain typed metadata and
aggregates only; raw harmful prompts, target responses, judge reasons, and
source row identifiers are not in this preregistration.

The defense compiler must operate on the registered abstraction. Any private
payload access needed to run an upstream method is isolated from the public
artifact and cannot cross build/selection/confirmation boundaries.

The behavior-risk category and the attack-dynamics taxonomy are different
namespaces. The former stratifies what risk domain a behavior belongs to; the
latter describes which response signal changed which next adaptation
operation. A defense implication written by an annotator is a testable
intervention hypothesis, not an observed gold label. Claim-bearing annotation
must preserve a blind human initial judgment, a versioned LLM proposal, the
human post-proposal judgment, disagreements, and adjudication rather than only
the final consensus row.

## Behavior registry without cherry-picking

The candidate source pool is HarmBench, AdvBench, and SALAD-Bench. Read-only
observations on 2026-11-16 recorded candidate revisions
`8e1604d1171fe8a48d8febecd22f600e462bdcdd`,
`098262edf85f807224e70ecd87b9d83716bf6b73`, and
`575d5369c5355c0ed76e27860a889aa2f3c3e0e5`, respectively. Their repository
license endpoints reported MIT, MIT, and Apache-2.0. These observations are not
G0 verification: the complete license bytes, dataset-specific terms, exact
source files, and local hashes still have to be audited and frozen. No behavior
payload or source row identifier appears in the public registry.

The private registry construction order is fixed:

1. source-integrity and license check;
2. deterministic Unicode/whitespace canonicalization;
3. exact hash grouping across sources;
4. semantic-similarity graph at cosine threshold 0.92;
5. blinded boundary adjudication; and
6. connected-component cluster assignment.

Adjudicators cannot see attack method, attack outcome, defense condition, or
split assignment. All exclusions receive a reason code. Cross-source duplicates
belong to one semantic cluster, so paraphrases cannot leak across splits.

Clusters, not rows, are assigned by an HMAC-derived value:

| Interval | Split | Fraction | Permitted use |
|---|---:|---:|---|
| 0000–4999 | Build | 0.50 | Attack memory and defense-candidate generation |
| 5000–7499 | Selection | 0.25 | Candidate, token-budget, and ablation selection |
| 7500–9999 | Confirmation | 0.25 | One sealed final evaluation only |

The private salt is committed at G2. Sampling is stratified by source and broad
safety category, then ordered with a distinct private HMAC salt. Manual example
selection and outcome-based sampling are prohibited. The per-stratum cap is
intentionally still `null`: it must be fixed by a blinded power analysis using
excluded pilot clusters before G2. A null cap blocks the main experiment; it is
not permission to choose the sample size after seeing results.

## Resource fairness

The primary comparison uses an equal target-generation-call budget:

- 20 target calls per registered episode;
- at most 512 target output tokens per call;
- at most 1,024 attacker output tokens per call;
- 120 seconds per call and 1,800 seconds per episode;
- five fixed attacker seeds; and
- stop on first strict success, call-cap exhaustion, or terminal failure.

Method-native search, branching, and pruning are preserved inside that cap and
fully logged. A second native-budget track is diagnostic only and cannot rank
methods against each other. Target, attacker, and judge calls/tokens, wall time,
and peak accelerator memory are reported separately.

Only an attested infrastructure error permits one retry with the same seed.
Retries cannot depend on an unfavorable model outcome.

## Immutable event ledger

Every registered run produces append-only JSONL with:

- a monotonic event sequence;
- previous-event hash;
- SHA-256 over canonical event JSON;
- the run-manifest hash in the first event; and
- the terminal chain hash in the sealed run manifest.

The ledger records run/episode boundaries, memory reads, attack candidates,
target and judge completion metadata, adaptation transitions, every memory
decision, and final outcomes. Required terminal outcomes include strict success,
ordinary attack failure, safe completion/refusal, budget exhaustion, invalid
attacker output, attacker/target/judge timeouts, infrastructure errors, policy
filter blocks, and cancellation before a target call.

Timeouts and missing judges are never relabeled as defense success.
Infrastructure missingness is reported separately with a conservative
sensitivity analysis. All registered episodes must have one terminal outcome;
failures are evidence, not rows to delete.

## Leave-one-method-out design

Five frozen folds train the memory-to-prompt compiler on four methods and test
live adaptation by the fifth. For example, the PAIR-held-out fold uses only TAP,
Crescendo, GPTFuzzer, and AutoDAN-Turbo memory during prompt construction.
Equivalent folds hold out each other method once.

This is stronger than random prompt-level splitting because the withheld
search/adaptation operator is absent from construction. A successful result
therefore measures method-family transfer rather than near-duplicate recall.

Fold isolation begins before prompt compilation. Any data-induced taxonomy,
annotation example, codebook revision, calibration item, or defense invariant
for a fold may use only its four training methods. A universal top-level
ontology may be shared only if it was frozen before registered method data,
using prior work and permanently excluded legacy pilots. A pattern first seen
in the held-out method remains `unmapped` for that fold and cannot be added
after observing the result.

## Registered controls and endpoints

All defense prompts are token matched where applicable. The six conditions are:

1. native target with no added defense;
2. generic safety prompt;
3. single-method memory prompt;
4. frequency-only memory prompt;
5. linkage-broken memory prompt; and
6. heterogeneous trajectory-memory prompt.

The primary safety endpoint is cluster-macro strict episode ASR under the equal
target-call budget. Macro aggregation occurs within source and category before
the global average. The defense must also satisfy a preregistered benign-utility
non-inferiority margin and prompt-token budget. Uncertainty uses a fixed-seed
cluster bootstrap, and primary contrasts use Holm correction.

Selection and pilot data cannot enter the primary confirmation analysis. The
confirmation split cannot be used for prompt selection or debugging.

## Gates G0–G6

| Gate | Required evidence | Failure consequence |
|---|---|---|
| G0 | Revisions/licenses/models/configs/seeds/budgets/judge/ledger frozen and hashed | No adapter or model launch |
| G1 | All five adapters pass structural parity and budget reconciliation | No universe claim or main collection |
| G2 | Eligibility, dedup, clusters, power, and split manifests frozen | No behavior sampling or attack-memory collection |
| G3 | Pilot ledger is complete and all outcomes reconcile | Repair instrumentation on new excluded pilot clusters |
| G4 | Build-only memory collection records all candidate/decision paths | Invalidate affected run and preserve failure ledger |
| G5 | Selection-only prompt choice; prompt/compiler/ablations frozen | Amend and restart before opening confirmation |
| G6 | One sealed live-adaptive, held-out-method, three-target confirmation | Report null/negative result without confirmation retuning |

Gates are sequential and fail closed. A passed gate needs a content-addressed
manifest; changing a frozen artifact creates a new preregistration/run ID.

## Validation

Run from the repository root:

```bash
python3 research/scripts/validate_adaptive_attack_preregistration.py
python3 -m pytest -q research/tests/test_adaptive_attack_preregistration.py
```

The validator is CPU-only, performs no network request, starts no model, and
allocates no GPU. It rejects duplicate JSON keys, incomplete method coverage,
judge leakage into the primary arm, malformed leave-one-method-out folds,
missing timeout/failure outcomes, weakened hash-chain requirements, cross-split
contract mismatches, premature freeze claims, raw payload-bearing fields, and
local filesystem paths in the public bundle.

## Next executable work after this scaffold

1. Complete G0 locally: independently re-resolve the observed dataset commits,
   retain complete license and source-file hashes, freeze model/runtime
   revisions, and emit a content-addressed manifest.
2. Implement each adapter against its exact candidate commit without changing
   the upstream semantics; generate one parity report per method.
3. Pass G1 before scheduling a multi-model pilot.
4. Build the private behavior registry, blinded power analysis, and salted split
   commitment; pass G2.
5. Run a small instrumentation-only pilot on permanently excluded clusters and
   audit the ledger before any memory collection.

GPU availability is never inferred from this document. Immediately before any
post-G1 launch, the runtime must select only GPUs with no compute process,
capture process identity and model/run metadata, arm independent cleanup, and
stop every server started by the run on completion or failure.
