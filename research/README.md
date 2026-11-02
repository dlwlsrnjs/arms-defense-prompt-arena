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
