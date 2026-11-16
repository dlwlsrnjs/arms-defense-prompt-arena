# AAMD benchmark I/O starter contract v1

This directory provides a **syntax-only, payload-free starter contract** for
AAMD tracks T1--T5. It does not claim that a deterministic projection builder,
hidden scorer, metric implementation, baseline, or benchmark result exists.
Those components remain blocked at **G2 pending**.

## Files

- `research/schemas/aamd-benchmark-instance-v1.schema.json`: one input envelope
- `research/schemas/aamd-benchmark-prediction-v1.schema.json`: one prediction envelope
- `research/fixtures/aamd-benchmark-io-v1/excluded-demo-*.json`: non-claim fixtures

Every envelope binds to an exact `projection_version`, ordered
`visible_fields`, and the SHA-256 of the compact canonical JSON array of those
fields. Changing the order or one field invalidates the envelope. All nested
objects are closed with `additionalProperties: false`.

T2 is deliberately split: T2a reproduces observed retrieval behavior and does
not support a causal claim; T2b ranks retrievals under M5 intervention or a
preregistered downstream-effect eligibility rule. T3 contains only abstract
history codes and cannot carry attack or response text. T4 predicts exactly
four codebook-valued fields. T5 accepts only a frozen, content-addressed
artifact manifest; prompt or executable contents are transferred separately by
the controlled evaluator.

## Validate with `jsonschema`

The fixtures are arrays for compact review, so validate each element:

```bash
python - <<'PY'
import json
from pathlib import Path
from jsonschema import Draft202012Validator

root = Path("research")
for stem, schema_name in (
    ("instances", "aamd-benchmark-instance-v1.schema.json"),
    ("predictions", "aamd-benchmark-prediction-v1.schema.json"),
):
    schema = json.loads((root / "schemas" / schema_name).read_text())
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    rows = json.loads((root / "fixtures" / "aamd-benchmark-io-v1" /
                       f"excluded-demo-{stem}.json").read_text())
    for row in rows:
        validator.validate(row)
    print(stem, len(rows), "valid")
PY
```

For a single extracted envelope, the package CLI is also usable:

```bash
python -m jsonschema \
  -i one-instance.json \
  research/schemas/aamd-benchmark-instance-v1.schema.json
```

`excluded_demo` rows are examples only. They must never enter a paper
denominator, leaderboard, or defense-effect claim. A claim-bearing release
still requires the G2 deterministic builder, leakage tests, hidden references,
scorer and metric golden tests, followed by the later preregistered gates.
