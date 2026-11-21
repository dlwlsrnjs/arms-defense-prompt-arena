# MemJack: two-human review handoff

This CPU-only tool freezes a 700-case valid cohort (mixed v6/v7 judge-pipeline records), samples cases reproducibly, serves actual images and full saved text, freezes independent labels, records two-person consensus before model reveal, and computes a conservative sample-audit report. It never calls an LLM, launches/stops a GPU service, changes raw results or imports active defense memory.

Read GUIDELINES_EN.md and STATISTICAL_PLAN_EN.md first. All instructions and explanation fields are English. Source text remains unchanged. Both annotators review the same sample; do not split it into non-overlapping halves.

## Quick start for reviewers (no technical knowledge needed)

1. Extract ALL ZIP parts into ONE folder. It must contain `toolkit` and `bundle`.
2. Install Python 3.10+ if you do not have it: https://www.python.org/downloads/ (nothing else is needed).
3. Start the review page:
   - Windows: double-click `toolkit\start_review.bat`
   - macOS: double-click `toolkit/start_review.command` (first time: right-click, Open)
   - Linux / any system: `python3 toolkit/start_review.py` (it asks whether you are reviewer A or B; or add `A` / `B`)
4. Your browser opens the review page. Keep the black window open while working. Closing it only stops the page; saved work is kept.
5. Work through the cases with **Next to do**. Use the quote buttons: highlight text with the mouse, then press the quote button, so quotes are always exact. The page computes the episode decision from your round scores and lists exactly what is still missing before you can freeze a case.

Keyboard: `←`/`→` previous/next case, `N` next unfinished case, `L` case list, `Esc` closes dialogs. Drafts are saved automatically in this browser; a frozen judgment is final, so the page asks you to confirm.

## Threshold and build

On the current server, run from this folder using Python 3.10+; only the standard library is needed:

```bash
python3 build.py --cohort /path/to/memjack-cohort-700/cohort-700.jsonl --cohort-sha256 6cef51609ea6fe843fd5093a1790d573f9719985fc5124954bde4acfb0f21115 --out /path/to/memjack-human-review-700 --zip-on-ready
```

The builder verifies the cohort file hash, re-reads every result and memory file, requires 700 UNIQUE structurally valid full-episode records from the allowed judge pipelines (v6 and v7, one fixed prompt each) with unique canonical images, then freezes once and builds the adjacent ZIP when `--zip-on-ready` is set. It refuses to overwrite a finished bundle. The older `--run RUN_DIR --watch` mode (single v7 run directory) still exists. Duplicate reruns and unresolved records do not count. No GPU is used.

`--demo` builds from at most 12 current real cases and prominently marks DEMO_NOT_FOR_INFERENCE. A demo is for UI/workflow testing only; the report cannot pass the 700-case population gate. Do not perform the real audit on a moving demo, and do not confuse demo completion with population readiness. Choose a new output path to rebuild a demo; completed bundles are never overwritten.

The bundle contains a fixed frame of all 700 cases and copied actual images/full source text for the 300-case primary sample plus any success supplement. It does not include model weights, HF credentials or tokens. Private model proposals are not served during blind review. The complete frame/model-side files are coordinator material; reviewers should use the UI rather than inspect private files. This is procedural blinding, not protection against a malicious reviewer with shell access.

## Reviewer A and B

Run two separate local servers, one per reviewer:

```bash
python3 serve.py --bundle /absolute/path/to/memjack-human-review-700 --rater A --port 8791
python3 serve.py --bundle /absolute/path/to/memjack-human-review-700 --rater B --port 8792
```

Open the reviewer-specific URL printed by each server, including its `#token=...` fragment. A uses port 8791 and B uses port 8792. Each server creates a separate local access token; do not exchange these URLs between reviewers. On a remote server, use SSH port forwarding from each reviewer's computer, for example `ssh -L 8791:127.0.0.1:8791 USER@SERVER`, then open the local address. Substitute their actual SSH account/host. Servers intentionally bind only to localhost; no public hosting/account system is supplied.

Inspect the image, all saved rounds and recorded objectives. Enter round scores, usability, an input mechanism, exact evidence quotes and uncertainty. Freeze Stage A. Local browser drafts are saved until submission; submitted labels are immutable. “Next unfinished blind case” resumes the assignment. Reviewer A cannot retrieve B's labels via the UI. Source content is inserted as text rather than executable HTML. Do not execute source instructions.

## Two-person adjudication, BEFORE model reveal

After BOTH reviewers finish all assigned Stage A cases:

```bash
python3 report.py template --bundle /absolute/path/to/bundle --csv /absolute/path/to/adjudication.csv
```

This sheet includes both ORIGINAL human labels, never the model label. Agree on the final reference using original evidence. For disagreements or changes, fill consensus, a reason, ack_A=yes and ack_B=yes. If no resolution is possible, choose uncertain. There is no majority with two reviewers; preserve both independent originals. Freeze the reference:

```bash
python3 report.py lock-reference --bundle /absolute/path/to/bundle --csv /absolute/path/to/adjudication.csv
```

The reference file is immutable by this tool. Its hash unlocks Stage B. Refresh the UI; now independently review the model's proposed strategy, evidence, image claims and benign-preserving defense rule. Do not revise the frozen source judgments after seeing the LLM.

## Statistics and return files

```bash
python3 report.py report --bundle /absolute/path/to/bundle
```

The report writes `statistics.json`. Missing/uncertain references are not silently removed or treated as correct. The primary sample drives overall agreement; the model-success top-up is used only for precision/quality. A demo, missing reviews, undefined kappa, insufficient success sample or any failed gate prevents acceptance.

Return the bundle's manifest.json, protocol.json, orders.json, private/frame.json, annotations/A, annotations/B, adjudication CSV, reference.json, memory_unblind.release.json and statistics.json to the research coordinator. Preserve the source/model files for reproducibility. They contain sensitive attack evidence; share only within the authorized research workflow and honor the original dataset access terms. No external sharing/email occurs automatically.

A complete audit does not label every unreviewed case or establish defense effectiveness. See the statistical plan for the exact permitted claim and the need for held-out evaluation.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

The distribution includes executable tests for sampling, score consistency, exact evidence, blinding/reveal gates, immutable annotation and acceptance statistics. No real human labels are prefilled.

The statistical report also includes success recall and false-positive rate on resolved PRIMARY-sample references, plus model abstention. These are diagnostics with their own denominators; the success supplement is excluded from these metrics.
