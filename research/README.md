# Research code snapshot

This directory contains the public, clean-room research code behind the
DEFENDER VS ARMS prototype. It is not the official ARMS implementation.

The snapshot focuses on the reproducible parts of the current work:

- memory-to-system-prompt compilation and exact-token prompt matching;
- native-only D1 calibration contracts and frozen first-move cassettes;
- response-conditioned ARMS execution after the frozen first move;
- independent multimodal, policy-completion, and capability-harm judgments;
- fail-closed Stage-0 orchestration and provenance validation;
- benign-utility and over-refusal evaluation helpers.

## Judge protocol v5

`armor-axis-judge-v5-mm` gives each evaluation axis at most two attempts. A
retry keeps the same evaluation payload, seed, and token budget, and adds only
a fixed instruction to emit the required JSON immediately. Successful first
attempts are unchanged. Two failed attempts remain censored and fail closed.
Only hashes, character counts, status codes, and `attempt_count` are retained;
raw judge output and rationale are not persisted.

The retry exists to prevent a single transient client or JSON-formatting error
from silently becoming a defense success. It does not retry based on the score.

## Public/private boundary

This repository intentionally excludes:

- attack and target-response text;
- warmed memory snapshots and private cassettes;
- model checkpoints, local paths, service PID files, and logs;
- pilot run directories and unpublished per-example results.

The YAML files under `configs/` are portable examples. Pin real model
revisions and provide your own externally managed OpenAI-compatible endpoints.

The public test set contains only tests that are self-contained in this
snapshot. Fixture-dependent pilot tests remain private with their redacted
evaluation artifacts.

## Verify

From this directory:

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
pytest -q tests
```

For exact-token selection, provide three candidate manifests and a writable
output directory explicitly:

```bash
python scripts/select_armor_token_matched.py \
  --generic /path/to/generic.json \
  --matched /path/to/memory-matched.json \
  --shuffled /path/to/label-shuffled.json \
  --tokenizer /path/to/local-qwen-tokenizer \
  --out /path/to/output
```

The live runner never starts model servers or allocates GPUs. Server lifecycle
must be managed separately, and a run is rejected when frozen hashes,
provenance, memory isolation, or evaluator identity do not match.


## Portable AAMD runtime (local server adaptation, 2026-11-18)

All five offline tools now share `scripts/aamd_runtime_config.py`. Set
`AAMD_RUNTIME_CONFIG` to an **absolute** JSON profile path with `runtime_root`,
`model_path`, `vllm_executable`, `vllm_version`, and
`vllm_entrypoint_sha256`. The example shape below is local-only: create
`research/configs/aamd-runtime.local.json` (gitignored) and use actual absolute
paths. The metadata/model revision, prompt, taxonomy and decoding remain frozen.
Unknown profile keys and relative paths are rejected. The launch manager checks
the installed vLLM version and entrypoint hash; selecting a new runtime does not
claim reproduction of the previous host's vLLM 0.28 environment.

```json
{
  "runtime_root": "/absolute/project/research/runtime/aamd",
  "model_path": "/absolute/models/Qwen2.5-VL-32B-Instruct",
  "vllm_executable": "/absolute/venv/bin/vllm",
  "vllm_version": "0.16.0",
  "vllm_entrypoint_sha256": "<actual 64-character SHA-256>"
}
```

Run from the repository root with a suitable Python environment:

```bash
export AAMD_RUNTIME_CONFIG="$PWD/research/configs/aamd-runtime.local.json"
python research/scripts/build_aamd_rcat7_pilot_source.py \
  --output-dir "$PWD/research/runtime/aamd/source-20261118" --chunk-size 24
python research/scripts/run_aamd_32b_labeling.py \
  --source-dir "$PWD/research/runtime/aamd/source-20261118" \
  --run-root "$PWD/research/runtime/aamd/smoke-gpu0-20261118" \
  --run-id smoke-gpu0-20261118 --gpu 0 --port 18232 \
  --bundle-limit 1 --wait-seconds 1 --poll-seconds 1 \
  --service-deadline-seconds 3600 --startup-seconds 900
```

`--bundle-limit 1` validates all frozen inputs and review IDs before allocating
anything, then labels only the first bundle (24 tasks with the above chunk size).
The result records `selection_scope=smoke_subset` and the selected bundle count;
it is not a completed 307-task run. Use a fresh run directory on every attempt.
GPU timeout writes `blocked_gpu_busy` with zero model-server launches/requests.
The manager still requires an empty GPU; background keepalive processes also
count as occupied. This adaptation does not kill or bypass unrelated processes.

A permission-denied vLLM child environment is accepted only through a live
captured leader, same UID/session/PGID, later start time, vLLM command identity,
and membership on the exact captured GPU UUID. Unrelated or unverifiable
children still fail closed. Shutdown continues to validate identity before
signaling and checks the captured port/processes afterward.


### Automatic available-GPU queue

`research/scripts/queue_aamd_32b_labeling.py` scans the explicitly listed GPUs
(default 0 and 1), waits up to 24 hours, and launches the managed runner once on
an available device. Default polling is 30 seconds; `--bundle-limit 1` means one
24-task smoke bundle with the prepared sources. The independent server watchdog
has a one-hour default deadline. A pre-inference allocation race returns to waiting within the same wait
deadline only after verified cleanup; actual inference or cleanup failure is
terminal. Availability must be confirmed continuously for 30 seconds before launch. The runtime lock
prevents duplicate queues. Source, profile and execution-code hashes are frozen;
changing them stops the queue before it starts a service.

The default GPU policy remains strict. An optional `allowed_background_processes`
profile entry can exempt **one** existing `gpu_keepalive.py` process only, by exact
PID, Linux process start ticks, UID, argv SHA-256, and a maximum GPU-memory cap
of 1024 MiB. Fingerprints are rechecked during allocation and monitoring. An
unrecognized process, PID reuse or excess/unattributed memory blocks the GPU.
The exemption is copied into the captured service identity for the watchdog;
keepalive is never stopped or signaled. This replaces the earlier requirement to
remove keepalive for this explicitly configured queue only.

The prepared local queue profile is
`research/runtime/aamd/auto-queue-runtime.local.json`. A queue's `queue-plan.json`
contains frozen provenance, and `queue-status.json` shows waiting, running,
completed, failed, expired or cancelled. Inspect the named `run_root` and its
`labeling-result.json` for actual results; waiting is never an inference result.


The local vLLM launcher uses a UID-owned short `/tmp/aamd-<uid>-<digest>`
symlink to the run's own `tmp/` directory for `TMPDIR` and
`VLLM_RPC_BASE_PATH`. This avoids Linux's 107-byte Unix socket path limit while
keeping backing files under the configured runtime root. Existing aliases must
match the exact owner and target; conflicting files or links are rejected.


### 32B proposal-format diagnostic and constrained-output pilot

A real unconstrained local 32B request returned HTTP 200 but failed strict JSON
validation: it wrapped the JSON in a Markdown code fence and also proposed a
non-mapped benign-confound combination that violates the codebook. Those runs
remain failed; no proposal was repaired or promoted.

The optional `--structured-output` flag is forwarded by the queue and managed
runner to the generator. It adds a per-task JSON Schema with frozen code enums,
allowed evidence handles, exact locked-axis hash and legal status/confound
combinations. The model still chooses labels and rationales; the original strict
validator remains authoritative. The request hash includes the schema, and the
manifest transport records `rcat7-constrained-json-schema-v1`. This is an explicit
pilot decoding variant, not the original unconstrained protocol or confirmed
annotation accuracy. The default remains unconstrained.

`--save-proposal-diagnostics` records private model proposal text beside the
manifest with mode 0600. These payload-free diagnostic files are gitignored.
Parser/validation failures now record the specific `validation_error`; malformed
outputs still fail closed with no final review bundle. `--generation-config vllm`
prevents checkpoint generation defaults from silently supplying extra sampling
penalties.


### Full 307-task labeling run (2026-11-19)

The full prepared source contains 13 bundles (12 x 24 + 19 = 307 tasks).
Use `--bundle-limit 13 --service-deadline-seconds 21600 --structured-output`
with the queue to run the whole source rather than the one-bundle smoke test.
The full run is a new execution; the earlier 24-task smoke test is preserved
separately and is not added to the 307-task denominator.

Generator `generation-manifest-NNN.progress.json` files update only after each
proposal passes the original strict validator. Queue heartbeats distinguish
`validated_tasks` from `published_tasks`, since final review bundles are written
atomically after a whole bundle passes. `total_tasks=307` records the selected
scope; only queue `completed` plus the final manifest and cleanup receipt mark
completion. The `active-queue.json` pointer identifies the current run.
