# AAMD 32B labeling handoff (2026-11-18)

This note records the exact stopped state of the AAMD RCAT-7 32B labeling
pipeline so that work can continue on another machine without treating an
incomplete pilot as experimental evidence.

## What is implemented

- Deterministic, payload-free RCAT-7 source-bundle construction from the
  pinned `attack-memory-v1` public artifact.
- Strict 32B proposal generation with frozen taxonomy, prompt, decoding, local
  endpoint, record/queue commitments, and fail-closed output validation.
- Ephemeral vLLM lifecycle management with GPU emptiness checks, captured
  process identity, run-scoped caches under `/data1`, an independent deadline
  watchdog, and explicit cleanup verification.
- Runtime provenance binding from the managed vLLM identity into generation
  manifests without claiming full model-weight content hashes.
- Validated review-bundle import tooling and a service-principal import route
  for the human-review workspace.
- CPU contract, tamper, lifecycle, importer, and Site integration tests.

## Last GPU attempt: invalid for inference/results

The stopped run used this local runtime root (not committed):

`/data1/users/ljk98/Amrs-runtime/aamd/run-20261118-gpu3-32b-v5`

The Qwen2.5-VL-32B model loaded on GPU 3, but the server received **zero chat
completion POST requests**. All 13 source bundles failed locally before HTTP
inference with:

`contract error: output_bundle_id must differ from the source bundle ID`

The frozen source IDs are shaped like:

`attack-memory-v1-rcat7-pilot-000`

The runner currently derives the output ID with a `-source-` string
replacement. That token is absent from the real ID, so the derived output ID is
unchanged. This must be fixed and regression-tested against the real ID shape
before another GPU launch. Output IDs should be deterministic, contract-valid,
and distinct, for example:

`attack-memory-v1-rcat7-review-000`

The mapping for every source bundle should be precomputed and validated before
GPU polling or model loading.

## Cleanup edge case found during the stopped run

The first explicit cleanup attempt could not read
`/proc/<EngineCore PID>/environ` and therefore failed closed while verifying the
vLLM EngineCore child. The server subsequently exited, and a second verified
stop confirmed all of the following:

- captured port closed;
- run processes gone;
- GPU 3 compute processes gone;
- GPU 3 memory usage returned to 0 MiB;
- watchdog stopped.

The manager should retain strict leader identity checks and add a narrow
fallback for an unreadable vLLM child environment: same UID, same captured
PGID/SID, start time after the leader, unbroken live ancestry to the captured
leader, and membership on the captured GPU UUID. An unreadable unrelated
process must still be rejected. Add both positive and negative regression
tests before relying on this fallback.

## Required next-run sequence

1. Fix and preflight all output bundle IDs before GPU allocation.
2. Fix and test the permission-restricted EngineCore identity fallback.
3. Run the AAMD CPU/contract/Site test suites.
4. Use a fresh run root and an actually empty GPU; never co-locate.
5. Run one source bundle first and require four pieces of evidence:
   - at least one `POST /v1/chat/completions` in the vLLM log;
   - non-zero GPU utilization during generation;
   - one contract-valid output bundle and generation manifest;
   - verified shutdown with closed port, no run PIDs, and released VRAM.
6. Only after that smoke test succeeds, run all 13 bundles (307 tasks) from a
   new run root.

Do not report attack/defense effectiveness or a completed 32B labeling result
from the stopped run. It only demonstrated successful model loading and exposed
two lifecycle/contract bugs.

## Storage and GPU invariants

- Keep source and small metadata in the repository.
- Keep datasets, model weights, logs, caches, and generated results under
  `/data1/users/ljk98/Amrs-runtime` (or an equivalent large-data root on the new
  host), never the root filesystem.
- Capture and revalidate every launched PID; never signal a process not started
  and identity-captured by the current run.
- Stop every model server immediately after success or failure and retain the
  independent hard-deadline watchdog.
