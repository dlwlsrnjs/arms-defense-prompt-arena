from __future__ import annotations

import csv
import hashlib
import json
import math
import os
import re
import unicodedata
from collections import Counter, defaultdict
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1
PRIMARY_TRACKS = (
    "memory_warm",
    "defender_train",
    "sealed_eval_text",
    "sealed_eval_vlm",
    "benign_eval",
)
OUTPUT_FILENAMES = {track: f"{track}.jsonl" for track in PRIMARY_TRACKS}
QUICK_EVAL_FILENAME = "sealed_eval_quick.jsonl"


@dataclass(frozen=True)
class DatasetSpec:
    name: str
    aliases: tuple[str, ...]
    license: str
    upstream: str


DATASET_SPECS: tuple[DatasetSpec, ...] = (
    DatasetSpec(
        "harmbench",
        ("HarmBench",),
        "MIT",
        "https://github.com/centerforaisafety/HarmBench",
    ),
    DatasetSpec(
        "advbench",
        ("llm-attacks", "AdvBench"),
        "MIT",
        "https://github.com/llm-attacks/llm-attacks",
    ),
    DatasetSpec(
        "strongreject",
        ("strongreject", "StrongREJECT"),
        "MIT",
        "https://github.com/alexandrasouly/strongreject",
    ),
    DatasetSpec(
        "jailbreakbench",
        ("JBB-Behaviors", "JailbreakBench"),
        "MIT",
        "https://huggingface.co/datasets/JailbreakBench/JBB-Behaviors",
    ),
    DatasetSpec(
        "salad",
        ("Salad-Data", "SALAD-Bench", "SALAD-BENCH"),
        "Apache-2.0",
        "https://huggingface.co/datasets/OpenSafetyLab/Salad-Data",
    ),
    DatasetSpec(
        "xstest",
        ("xstest", "XSTest"),
        "CC-BY-4.0",
        "https://github.com/paul-rottger/xstest",
    ),
    DatasetSpec(
        "or_bench",
        ("or-bench", "OR-Bench", "bench-llm--or-bench"),
        "CC-BY-4.0",
        "https://huggingface.co/datasets/bench-llm/or-bench",
    ),
    DatasetSpec(
        "mm_safetybench",
        ("MM-SafetyBench", "MM_SafetyBench"),
        "CC-BY-NC-4.0",
        "https://github.com/isXinLiu/MM-SafetyBench",
    ),
)
SPECS_BY_NAME = {spec.name: spec for spec in DATASET_SPECS}


@dataclass(frozen=True)
class MediaRef:
    type: str
    path: str
    sha256: str | None
    available: bool


@dataclass
class Candidate:
    dataset: str
    query: str
    source_id: str
    source_split: str
    source_category: str
    track: str
    safety_label: str
    source_file: Path
    source_root: Path
    source_row: int | str
    modality: str = "text"
    media: tuple[MediaRef, ...] = ()
    context: str | None = None
    guard_text: str | None = None
    source_category_path: tuple[str, ...] = ()
    variant: str | None = None
    quick: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.query = _clean_text(self.query)
        if not self.query:
            raise ValueError("candidate query cannot be empty")
        if self.track not in PRIMARY_TRACKS:
            raise ValueError(f"unknown track: {self.track}")
        if self.safety_label not in {"harmful", "benign"}:
            raise ValueError(f"unknown safety label: {self.safety_label}")


@dataclass(frozen=True)
class BuildResult:
    output_dir: Path
    manifest: dict[str, Any]


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _json_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _clean_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, float) and math.isnan(value):
        return ""
    return re.sub(r"\s+", " ", str(value)).strip()


def normalize_text(value: str) -> str:
    """Return the deterministic representation used by exact decontamination."""
    value = unicodedata.normalize("NFKC", value).casefold()
    value = "".join(" " if unicodedata.category(char)[0] in {"P", "S", "Z"} else char for char in value)
    return re.sub(r"\s+", " ", value).strip()


def _slug(value: str) -> str:
    value = normalize_text(value).replace(" ", "_")
    return re.sub(r"[^a-z0-9_]+", "", value).strip("_") or "unknown"


_CATEGORY_RULES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("Child Safety", ("child", "minor", "csam")),
    ("Self-Harm", ("self harm", "suicide", "self injury")),
    ("Cyber Harm", ("cyber", "malware", "hacking", "intrusion", "vulnerability", "computer security")),
    ("Fraud/Deception", ("fraud", "decept", "scam", "phishing", "imperson", "forgery")),
    ("Privacy Violations", ("privacy", "personal data", "dox", "surveillance")),
    ("Sexual/Adult Content", ("sex", "sexual", "adult", "porn")),
    ("Hate/Harassment", ("hate", "harass", "toxic", "discrimin", "stereotyp", "representation")),
    ("Misinformation/Manipulation", ("misinformation", "disinformation", "manipulation", "erosion of trust")),
    ("Violence", ("violence", "physical harm", "weapon", "terror", "extrem")),
    ("Economic Harm", ("economic", "market manipulation")),
    ("Government Decision", ("government", "politic", "lobby", "public decision")),
    ("Sensitive Advice", ("health", "medical", "legal", "financial advice", "consultation")),
    ("Animal Abuse", ("animal abuse", "animal harm")),
    ("Non-violent Crime", ("illegal", "crime", "criminal", "drug", "regulated goods", "malicious use")),
)


def canonical_category(source_category: str, safety_label: str) -> str:
    if safety_label == "benign":
        return "Benign"
    normalized = normalize_text(source_category)
    for canonical, needles in _CATEGORY_RULES:
        if any(needle in normalized for needle in needles):
            return canonical
    return "General Harm"


def _normalized_name(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.casefold())


def _resolve_hf_snapshot(path: Path) -> Path:
    snapshots = path / "snapshots"
    if not snapshots.is_dir():
        return path
    ref = path / "refs" / "main"
    if ref.is_file():
        candidate = snapshots / ref.read_text(encoding="utf-8").strip()
        if candidate.is_dir():
            return candidate.resolve()
    children = sorted(child for child in snapshots.iterdir() if child.is_dir())
    return children[-1].resolve() if children else path


def locate_dataset_roots(
    source_root: str | Path,
    overrides: Mapping[str, str | Path] | None = None,
    *,
    allow_missing: bool = False,
) -> dict[str, Path]:
    """Locate curated upstream checkouts/snapshots without making network calls."""
    source_root = Path(source_root).expanduser().resolve()
    if not source_root.is_dir():
        raise FileNotFoundError(f"source root not found: {source_root}")
    overrides = dict(overrides or {})
    roots: dict[str, Path] = {}
    for name, value in overrides.items():
        if name not in SPECS_BY_NAME:
            raise ValueError(f"unknown dataset override {name!r}")
        path = _resolve_hf_snapshot(Path(value).expanduser().resolve())
        if not path.is_dir():
            raise FileNotFoundError(f"dataset root for {name} not found: {path}")
        roots[name] = path

    wanted = {spec.name for spec in DATASET_SPECS} - set(roots)
    alias_map = {
        spec.name: tuple(_normalized_name(alias) for alias in spec.aliases)
        for spec in DATASET_SPECS
    }
    candidates: list[Path] = [source_root]
    for current, dirnames, _filenames in os.walk(source_root):
        relative_depth = len(Path(current).relative_to(source_root).parts)
        dirnames[:] = [name for name in dirnames if not name.startswith(".") and name not in {"blobs", "refs"}]
        if relative_depth >= 4:
            dirnames[:] = []
            continue
        candidates.extend(Path(current) / name for name in dirnames)

    for name in sorted(wanted):
        matches: list[tuple[int, int, str, Path]] = []
        for candidate in candidates:
            normalized = _normalized_name(candidate.name)
            for alias in alias_map[name]:
                if normalized == alias:
                    matches.append((0, len(candidate.parts), str(candidate), candidate))
                elif alias and alias in normalized:
                    matches.append((1, len(candidate.parts), str(candidate), candidate))
        if matches:
            roots[name] = _resolve_hf_snapshot(min(matches)[-1]).resolve()

    missing = sorted({spec.name for spec in DATASET_SPECS} - set(roots))
    if missing and not allow_missing:
        raise FileNotFoundError(f"missing dataset roots below {source_root}: {', '.join(missing)}")
    return {name: roots[name] for name in sorted(roots)}


def _revision(root: Path) -> str | None:
    for index, part in enumerate(root.parts):
        if part == "snapshots" and index + 1 < len(root.parts):
            revision = root.parts[index + 1]
            if re.fullmatch(r"[0-9a-f]{7,64}", revision):
                return revision
    git = root / ".git"
    if not git.is_dir():
        return None
    head = git / "HEAD"
    if not head.is_file():
        return None
    value = head.read_text(encoding="utf-8").strip()
    if re.fullmatch(r"[0-9a-f]{40,64}", value):
        return value
    if value.startswith("ref: "):
        ref = git / value[5:]
        if ref.is_file():
            return ref.read_text(encoding="utf-8").strip()
        packed = git / "packed-refs"
        if packed.is_file():
            for line in packed.read_text(encoding="utf-8").splitlines():
                if line and not line.startswith(("#", "^")):
                    commit, ref_name = line.split(" ", 1)
                    if ref_name == value[5:]:
                        return commit
    return None


_TABLE_SUFFIXES = {".csv", ".json", ".jsonl", ".parquet"}


def _data_files(root: Path) -> list[Path]:
    return sorted(
        path for path in root.rglob("*")
        if path.is_file() and path.suffix.casefold() in _TABLE_SUFFIXES and ".git" not in path.parts
    )


_QUERY_KEYS = {
    "behavior", "goal", "forbidden_prompt", "question", "prompt", "augq", "daugq",
    "rephrased question", "rephrased question(sd)", "changed question",
}


def _looks_like_record(value: Mapping[str, Any]) -> bool:
    return bool({str(key).casefold() for key in value} & _QUERY_KEYS)


def _flatten_json(value: Any, inherited_split: str | None = None) -> Iterator[dict[str, Any]]:
    if isinstance(value, list):
        for item in value:
            if isinstance(item, Mapping):
                row = dict(item)
                if inherited_split and "__container_split" not in row:
                    row["__container_split"] = inherited_split
                yield row
        return
    if not isinstance(value, Mapping):
        return
    if _looks_like_record(value):
        row = dict(value)
        if inherited_split:
            row.setdefault("__container_split", inherited_split)
        yield row
        return
    for key in sorted(value, key=str):
        item = value[key]
        if isinstance(item, Mapping) and _looks_like_record(item):
            row = dict(item)
            row.setdefault("__source_key", str(key))
            if inherited_split:
                row.setdefault("__container_split", inherited_split)
            yield row
        elif isinstance(item, (list, Mapping)):
            yield from _flatten_json(item, str(key))


def _read_rows(path: Path) -> Iterator[tuple[int, dict[str, Any]]]:
    suffix = path.suffix.casefold()
    if suffix == ".csv":
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            yield from enumerate(csv.DictReader(handle), start=2)
        return
    if suffix == ".jsonl":
        with path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                if line.strip():
                    value = json.loads(line)
                    if isinstance(value, Mapping):
                        yield line_number, dict(value)
        return
    if suffix == ".json":
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
            yield from enumerate(_flatten_json(value), start=1)
        except json.JSONDecodeError:
            with path.open("r", encoding="utf-8") as handle:
                for line_number, line in enumerate(handle, start=1):
                    if line.strip():
                        item = json.loads(line)
                        if isinstance(item, Mapping):
                            yield line_number, dict(item)
        return
    if suffix == ".parquet":
        try:
            import pandas as pd  # pylint: disable=import-outside-toplevel
        except ImportError as exc:  # pragma: no cover - depends on optional runtime data format
            raise RuntimeError(f"pandas/pyarrow is required to read {path}") from exc
        try:
            frame = pd.read_parquet(path)
        except ImportError as exc:  # pragma: no cover - depends on optional runtime data format
            raise RuntimeError(f"a parquet engine such as pyarrow is required to read {path}") from exc
        yield from enumerate(frame.to_dict(orient="records"), start=1)


def _get(row: Mapping[str, Any], *names: str) -> str:
    lowered = {str(key).casefold(): value for key, value in row.items()}
    for name in names:
        value = _clean_text(lowered.get(name.casefold()))
        if value:
            return value
    return ""


def _relative(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.name


def _media_ref(path: Path, root: Path) -> MediaRef:
    available = path.is_file()
    return MediaRef(
        type="image",
        path=_relative(path, root),
        sha256=sha256_file(path) if available else None,
        available=available,
    )


def _source_id(row: Mapping[str, Any], row_number: int, *names: str) -> str:
    return _get(row, *names) or _get(row, "__source_key") or str(row_number)


def _pick_preferred(files: Sequence[Path], preferred: Sequence[str]) -> list[Path]:
    by_name = {path.name.casefold(): path for path in files}
    for name in preferred:
        path = by_name.get(name.casefold())
        if path:
            return [path]
    return []


def _harmbench(root: Path) -> Iterator[Candidate]:
    files = [path for path in _data_files(root) if path.name.casefold().startswith("harmbench_behaviors_")]
    chosen: list[Path] = []
    for kind in ("text", "multimodal"):
        matches = [path for path in files if f"_{kind}_" in path.name.casefold()]
        by_name = {path.name.casefold(): path for path in matches}
        split_files = [
            by_name[name]
            for name in (
                f"harmbench_behaviors_{kind}_val.csv",
                f"harmbench_behaviors_{kind}_test.csv",
            )
            if name in by_name
        ]
        chosen.extend(split_files or _pick_preferred(matches, (f"harmbench_behaviors_{kind}_all.csv",)))
    for path in sorted(set(chosen)):
        multimodal = "_multimodal_" in path.name.casefold()
        split_match = re.search(r"_(test|val|all)\.", path.name.casefold())
        split = split_match.group(1) if split_match else "official"
        for row_number, row in _read_rows(path):
            query = _get(row, "Behavior")
            if not query:
                continue
            context = _get(row, "ContextString")
            if context:
                # HarmBench contextual behaviors are defined by the pair. Keeping
                # ContextString only as metadata would silently change the task
                # seen by ARMS, so install it into the executable behavior seed.
                query = f"{context}\n\n{query}"
            media: tuple[MediaRef, ...] = ()
            if multimodal:
                image_name = _get(row, "ImageFileName")
                image_candidates = (
                    root / "data" / "multimodal_behavior_images" / image_name,
                    root / "data" / "behavior_datasets" / "multimodal_behavior_images" / image_name,
                    root / "data" / "images" / image_name,
                )
                image_path = next((candidate for candidate in image_candidates if candidate.is_file()), image_candidates[0])
                media = (_media_ref(image_path, root),)
            category_path = tuple(filter(None, (
                _get(row, "FunctionalCategory"), _get(row, "SemanticCategory")
            )))
            yield Candidate(
                dataset="harmbench",
                query=query,
                source_id=_source_id(row, row_number, "BehaviorID"),
                source_split=split,
                source_category=category_path[-1] if category_path else "unspecified",
                source_category_path=category_path,
                track=(
                    "memory_warm" if split == "val"
                    else "sealed_eval_vlm" if multimodal
                    else "sealed_eval_text"
                ),
                safety_label="harmful",
                source_file=path,
                source_root=root,
                source_row=row_number,
                modality="image_text" if multimodal else "text",
                media=media,
                context=context or None,
            )


def _advbench(root: Path) -> Iterator[Candidate]:
    files = [path for path in _data_files(root) if path.name.casefold() == "harmful_behaviors.csv"]
    if not files:
        files = [path for path in _data_files(root) if "advbench" in path.name.casefold()]
    for path in files:
        for row_number, row in _read_rows(path):
            query = _get(row, "goal", "prompt", "behavior")
            if query:
                yield Candidate(
                    dataset="advbench",
                    query=query,
                    source_id=_source_id(row, row_number, "id", "behavior_id"),
                    source_split="official_all",
                    source_category=_get(row, "category") or "unspecified",
                    track="memory_warm",
                    safety_label="harmful",
                    source_file=path,
                    source_root=root,
                    source_row=row_number,
                )


def _strongreject(root: Path) -> Iterator[Candidate]:
    files = [path for path in _data_files(root) if "strongreject" in path.name.casefold() and "result" not in path.name.casefold()]
    # The official repository retains historical snapshots under
    # ``previous_versions``.  Mixing them with the current 313-row release
    # silently creates a non-standard union benchmark, so prefer the current
    # top-level file and only fall back when an older checkout lacks it.
    current_full = [
        path for path in files
        if path.name.casefold() == "strongreject_dataset.csv"
        and "previous_versions" not in {part.casefold() for part in path.parts}
    ]
    full = [path for path in files if "small" not in path.name.casefold()]
    selected = current_full or sorted(full, key=lambda path: (len(path.parts), str(path)))[:1] or files[:1]
    quick_hashes: set[str] = set()
    for path in files:
        if "small" in path.name.casefold():
            for _row_number, row in _read_rows(path):
                query = _get(row, "forbidden_prompt", "prompt", "goal")
                if query:
                    quick_hashes.add(_sha256_bytes(normalize_text(query).encode("utf-8")))
    for path in selected:
        split = "small" if "small" in path.name.casefold() else "full"
        for row_number, row in _read_rows(path):
            query = _get(row, "forbidden_prompt", "prompt", "goal")
            if query:
                normalized_hash = _sha256_bytes(normalize_text(query).encode("utf-8"))
                yield Candidate(
                    dataset="strongreject",
                    query=query,
                    source_id=_source_id(row, row_number, "id", "prompt_id"),
                    source_split=split,
                    source_category=_get(row, "category") or "unspecified",
                    track="sealed_eval_text",
                    safety_label="harmful",
                    source_file=path,
                    source_root=root,
                    source_row=row_number,
                    quick=split == "small" or normalized_hash in quick_hashes,
                    metadata={"upstream_source": _get(row, "source")},
                )


def _jailbreakbench(root: Path) -> Iterator[Candidate]:
    files = [
        path for path in _data_files(root)
        if "behavior" in path.name.casefold() and "judge" not in path.name.casefold()
    ]
    for path in files:
        filename = path.name.casefold()
        path_label = "benign" if "benign" in filename else "harmful" if "harmful" in filename else ""
        for row_number, row in _read_rows(path):
            label = (_get(row, "label", "safety_label", "split") or path_label).casefold()
            benign = "benign" in label or label == "safe"
            query = _get(row, "Goal", "prompt", "query")
            if not query:
                continue
            upstream_source = _get(row, "Source")
            yield Candidate(
                dataset="jailbreakbench",
                query=query,
                source_id=_source_id(row, row_number, "Behavior", "id"),
                source_split="benign" if benign else "harmful",
                source_category=_get(row, "Category") or "unspecified",
                track="benign_eval" if benign else "sealed_eval_text",
                safety_label="benign" if benign else "harmful",
                source_file=path,
                source_root=root,
                source_row=row_number,
                quick=(not benign and normalize_text(upstream_source) == "original"),
                metadata={"upstream_source": upstream_source},
            )


def _salad(root: Path, warm_per_category: int = 10) -> Iterator[Candidate]:
    accepted = {"base_set.json", "attack_enhanced_set.json", "defense_enhanced_set.json"}
    files = [path for path in _data_files(root) if path.name.casefold() in accepted]
    warm_candidates: list[Candidate] = []
    train_candidates: list[Candidate] = []
    for path in files:
        name = path.name.casefold()
        attack = name == "attack_enhanced_set.json"
        query_names = ("augq", "question", "baseq") if attack else (
            ("daugq", "question", "baseq") if name == "defense_enhanced_set.json" else ("question", "baseq")
        )
        for row_number, row in _read_rows(path):
            query = _get(row, *query_names)
            if not query:
                continue
            categories = tuple(filter(None, (
                _get(row, "1-category"), _get(row, "2-category"), _get(row, "3-category")
            )))
            candidate = Candidate(
                dataset="salad",
                query=query,
                guard_text=_get(row, "baseq", "question") or query,
                source_id=_source_id(row, row_number, "aid", "did", "qid"),
                source_split=path.stem,
                source_category=categories[-1] if categories else "unspecified",
                source_category_path=categories,
                track="defender_train" if name in {"attack_enhanced_set.json", "defense_enhanced_set.json"} else "memory_warm",
                safety_label="harmful",
                source_file=path,
                source_root=root,
                source_row=row_number,
                variant=_get(row, "method", "dmethod") or None,
                metadata={"upstream_source": _get(row, "source")},
            )
            if candidate.track == "memory_warm":
                warm_candidates.append(candidate)
            else:
                train_candidates.append(candidate)

    grouped: dict[str, list[Candidate]] = defaultdict(list)
    for candidate in warm_candidates:
        grouped[candidate.source_category].append(candidate)
    for category in sorted(grouped):
        selected = sorted(
            grouped[category],
            key=lambda candidate: (
                0 if normalize_text(_clean_text(candidate.metadata.get("upstream_source"))) == "self instructed" else 1,
                _sha256_bytes(_guard_value(candidate).encode("utf-8")),
                candidate.source_id,
            ),
        )[:warm_per_category]
        yield from selected
    yield from sorted(train_candidates, key=_candidate_key)


def _xstest(root: Path) -> Iterator[Candidate]:
    files = [path for path in _data_files(root) if "xstest" in path.name.casefold() and "prompt" in path.name.casefold()]
    if not files:
        files = [path for path in _data_files(root) if path.name.casefold() == "xstest.csv"]
    for path in files:
        for row_number, row in _read_rows(path):
            query = _get(row, "prompt", "question", "query")
            if not query:
                continue
            label = normalize_text(_get(row, "label", "safety_label"))
            if label not in {"safe", "unsafe", "benign", "harmful"}:
                continue
            benign = label in {"safe", "benign"}
            category = _get(row, "type", "category") or "unspecified"
            yield Candidate(
                dataset="xstest",
                query=query,
                source_id=_source_id(row, row_number, "id"),
                source_split="safe" if benign else "unsafe",
                source_category=category,
                track="benign_eval" if benign else "sealed_eval_text",
                safety_label="benign" if benign else "harmful",
                source_file=path,
                source_root=root,
                source_row=row_number,
            )


def _or_bench(root: Path) -> Iterator[Candidate]:
    files = [path for path in _data_files(root) if "or-bench" in path.name.casefold() or "or_bench" in path.name.casefold()]
    for path in files:
        name = path.name.casefold()
        if "toxic" in name:
            track, safety, split = "sealed_eval_text", "harmful", "or-bench-toxic"
        elif "hard" in name:
            track, safety, split = "benign_eval", "benign", "or-bench-hard-1k"
        elif "80k" in name:
            track, safety, split = "defender_train", "benign", "or-bench-80k"
        else:
            continue
        for row_number, row in _read_rows(path):
            query = _get(row, "prompt", "question", "query")
            if query:
                yield Candidate(
                    dataset="or_bench",
                    query=query,
                    source_id=_source_id(row, row_number, "id"),
                    source_split=split,
                    source_category=_get(row, "category") or "unspecified",
                    track=track,
                    safety_label=safety,
                    source_file=path,
                    source_root=root,
                    source_row=row_number,
                )


def _mm_safetybench(root: Path) -> Iterator[Candidate]:
    question_dir = root / "data" / "processed_questions"
    files = sorted(question_dir.glob("*.json")) if question_dir.is_dir() else [
        path for path in _data_files(root) if "processed_questions" in path.parts
    ]
    tiny_path = root / "TinyVersion_ID_List.json"
    tiny_ids: dict[str, set[str]] | None = None
    if tiny_path.is_file():
        tiny_value = json.loads(tiny_path.read_text(encoding="utf-8"))
        tiny_ids = {}
        if isinstance(tiny_value, list):
            for item in tiny_value:
                if isinstance(item, Mapping):
                    scenario = _get(item, "Scenario")
                    ids = item.get("Sampled_ID_List", [])
                    if scenario and isinstance(ids, list):
                        tiny_ids[scenario] = {str(value) for value in ids}
        elif isinstance(tiny_value, Mapping):
            for scenario, ids in tiny_value.items():
                if isinstance(ids, list):
                    tiny_ids[str(scenario)] = {str(value) for value in ids}
    for path in files:
        scenario = path.stem
        for row_number, row in _read_rows(path):
            source_id = _source_id(row, row_number, "id")
            if tiny_ids is not None and source_id not in tiny_ids.get(scenario, set()):
                continue
            guard = _get(row, "Question", "Changed Question")
            variants = (
                ("SD", _get(row, "Rephrased Question(SD)")),
                ("SD_TYPO", _get(row, "Rephrased Question")),
                ("TYPO", _get(row, "Rephrased Question")),
            )
            for variant, query in variants:
                if not query:
                    continue
                image = root / "data" / "imgs" / scenario / variant / f"{source_id}.jpg"
                yield Candidate(
                    dataset="mm_safetybench",
                    query=query,
                    guard_text=guard or query,
                    source_id=f"{source_id}:{variant}",
                    source_split="official_all",
                    source_category=scenario,
                    track="sealed_eval_vlm",
                    safety_label="harmful",
                    source_file=path,
                    source_root=root,
                    source_row=row_number,
                    modality="image_text",
                    media=(_media_ref(image, root),),
                    variant=variant,
                )


ADAPTERS = {
    "harmbench": _harmbench,
    "advbench": _advbench,
    "strongreject": _strongreject,
    "jailbreakbench": _jailbreakbench,
    "salad": _salad,
    "xstest": _xstest,
    "or_bench": _or_bench,
    "mm_safetybench": _mm_safetybench,
}


def load_candidates(roots: Mapping[str, Path], *, salad_warm_per_category: int = 10) -> list[Candidate]:
    candidates: list[Candidate] = []
    for name in sorted(roots):
        if name not in ADAPTERS:
            raise ValueError(f"no adapter for dataset {name!r}")
        if name == "salad":
            candidates.extend(_salad(Path(roots[name]).resolve(), salad_warm_per_category))
        else:
            candidates.extend(ADAPTERS[name](Path(roots[name]).resolve()))
    return candidates


def _char_ngrams(value: str, size: int = 4) -> set[str]:
    compact = value.replace(" ", "_")
    if len(compact) <= size:
        return {compact}
    return {compact[index:index + size] for index in range(len(compact) - size + 1)}


def _near(value_a: str, value_b: str, threshold: float) -> bool:
    if value_a == value_b:
        return True
    if min(len(value_a), len(value_b)) < 16:
        return False
    grams_a = _char_ngrams(value_a)
    grams_b = _char_ngrams(value_b)
    union = len(grams_a | grams_b)
    jaccard = len(grams_a & grams_b) / union if union else 0.0
    if jaccard >= threshold:
        return True
    return SequenceMatcher(None, value_a, value_b, autojunk=False).ratio() >= threshold


def _hashed_ngrams(grams: set[str]) -> list[int]:
    return sorted(
        int.from_bytes(hashlib.blake2b(gram.encode("utf-8"), digest_size=8).digest(), "big")
        for gram in grams
    )


def _signature_keys(
    value: str,
    *,
    sketch_size: int = 32,
    band_size: int = 5,
) -> tuple[tuple[int, ...], ...]:
    """Return deterministic bottom-k LSH bands for near-duplicate lookup.

    Indexing individual low-hash n-grams creates very large posting lists for
    common language.  Consecutive bands keep the useful property of a bottom-k
    sketch -- very similar strings retain many identical runs -- while making
    accidental bucket collisions much rarer.  Overlapping bands are deliberate:
    a small number of inserted/deleted shingles cannot shift all remaining
    bands as it could with disjoint chunking.
    """
    hashes = _hashed_ngrams(_char_ngrams(value))[:sketch_size]
    if len(hashes) <= band_size:
        return (tuple(hashes),)
    return tuple(
        tuple(hashes[index:index + band_size])
        for index in range(len(hashes) - band_size + 1)
    )


class _NearIndex:
    def __init__(self, threshold: float):
        self.threshold = threshold
        self.values: list[tuple[str, set[str], Candidate]] = []
        self.buckets: dict[tuple[int, ...], list[int]] = defaultdict(list)

    def find(self, value: str) -> Candidate | None:
        grams = _char_ngrams(value)
        candidates: set[int] = set()
        # Probe uncommon bands first for deterministic, cache-friendly posting
        # list traversal.  Candidate verification remains exact with respect to
        # the module's existing _near predicate.
        keys = sorted(
            _signature_keys(value),
            key=lambda key: (len(self.buckets.get(key, ())), key),
        )
        for key in keys:
            candidates.update(self.buckets.get(key, ()))
        for index in sorted(candidates):
            existing, existing_grams, candidate = self.values[index]
            if value == existing:
                return candidate
            if min(len(value), len(existing)) < 16:
                continue
            union = len(grams | existing_grams)
            jaccard = len(grams & existing_grams) / union if union else 0.0
            if jaccard >= self.threshold or SequenceMatcher(
                None, value, existing, autojunk=False
            ).ratio() >= self.threshold:
                return candidate
        return None

    def add(self, value: str, candidate: Candidate) -> None:
        index = len(self.values)
        self.values.append((value, _char_ngrams(value), candidate))
        for key in _signature_keys(value):
            self.buckets[key].append(index)


_TRACK_PRIORITY = {
    "sealed_eval_text": 0,
    "sealed_eval_vlm": 0,
    "benign_eval": 1,
    "defender_train": 2,
    "memory_warm": 3,
}
_DATASET_PRIORITY = {
    "strongreject": 0,
    "jailbreakbench": 1,
    "harmbench": 2,
    "mm_safetybench": 3,
    "xstest": 4,
    "or_bench": 5,
    "salad": 6,
    "advbench": 7,
}


def _candidate_key(candidate: Candidate) -> tuple[Any, ...]:
    return (
        _TRACK_PRIORITY[candidate.track],
        0 if candidate.quick else 1,
        _DATASET_PRIORITY.get(candidate.dataset, 99),
        _relative(candidate.source_file, candidate.source_root),
        str(candidate.source_id),
        candidate.variant or "",
        _sha256_bytes(candidate.query.encode("utf-8")),
    )


def _content_key(candidate: Candidate) -> str:
    media = tuple((item.type, item.sha256 or item.path) for item in candidate.media)
    return _sha256_bytes(_json_bytes((normalize_text(candidate.query), candidate.modality, media)))


def _guard_value(candidate: Candidate) -> str:
    return normalize_text(candidate.guard_text or candidate.query)


def _preserve_official_multimodal_variants(current: Candidate, existing: Candidate) -> bool:
    return (
        current.track == existing.track == "sealed_eval_vlm"
        and current.dataset == existing.dataset == "mm_safetybench"
        and current.source_id.split(":", 1)[0] == existing.source_id.split(":", 1)[0]
        and current.variant != existing.variant
    )


def deduplicate_candidates(
    candidates: Sequence[Candidate],
    *,
    near_threshold: float = 0.92,
) -> tuple[list[Candidate], dict[str, int]]:
    if not 0.8 <= near_threshold <= 1.0:
        raise ValueError("near_threshold must be between 0.8 and 1.0")
    exact: dict[str, Candidate] = {}
    # Near-decontamination exists to protect evaluation from train/warm
    # leakage.  Keeping only the eval/benign partition in this index preserves
    # that guarantee while avoiding an O(train^2) index over the much larger
    # defender-training corpus.  Exact duplicate removal remains global.
    protected_near = _NearIndex(near_threshold)
    kept: list[Candidate] = []
    stats: Counter[str] = Counter()
    for candidate in sorted(candidates, key=_candidate_key):
        content_key = _content_key(candidate)
        guard = _guard_value(candidate)
        existing = exact.get(content_key)
        if existing is not None:
            reason = "eval_decontamination_exact" if _TRACK_PRIORITY[candidate.track] > 1 and _TRACK_PRIORITY[existing.track] <= 1 else "exact_duplicate"
            stats[reason] += 1
            continue
        similar = protected_near.find(guard)
        if similar is not None and not _preserve_official_multimodal_variants(candidate, similar):
            reason = "eval_decontamination_near" if _TRACK_PRIORITY[candidate.track] > 1 and _TRACK_PRIORITY[similar.track] <= 1 else "near_duplicate"
            stats[reason] += 1
            continue
        exact[content_key] = candidate
        if _TRACK_PRIORITY[candidate.track] <= 1:
            protected_near.add(guard, candidate)
        kept.append(candidate)
    stats["input"] = len(candidates)
    stats["retained"] = len(kept)
    return kept, dict(sorted(stats.items()))


def _candidate_to_row(candidate: Candidate, source_file_hash: str, revision: str | None) -> dict[str, Any]:
    spec = SPECS_BY_NAME[candidate.dataset]
    normalized_query = normalize_text(candidate.query)
    media = [
        {"type": item.type, "path": item.path, "sha256": item.sha256, "available": item.available}
        for item in candidate.media
    ]
    content_payload = {
        "query": normalized_query,
        "modality": candidate.modality,
        "media": [(item["type"], item["sha256"] or item["path"]) for item in media],
    }
    content_hash = _sha256_bytes(_json_bytes(content_payload))
    category = canonical_category(candidate.source_category, candidate.safety_label)
    identifier = f"{candidate.dataset}:{_slug(candidate.source_id)}:{content_hash[:16]}"
    metadata = {key: value for key, value in sorted(candidate.metadata.items()) if _clean_text(value)}
    return {
        "schema_version": SCHEMA_VERSION,
        "id": identifier,
        "behavior": candidate.query,
        "query": candidate.query,
        "context": candidate.context,
        "risk_category": category,
        "track": candidate.track,
        "safety_label": candidate.safety_label,
        "source": candidate.dataset,
        "source_split": candidate.source_split,
        "source_category": candidate.source_category,
        "source_category_path": list(candidate.source_category_path) or [candidate.source_category],
        "canonical_category": category,
        "modality": candidate.modality,
        "media": media,
        "license": spec.license,
        "provenance": {
            "dataset": candidate.dataset,
            "upstream": spec.upstream,
            "upstream_revision": revision,
            "source_file": _relative(candidate.source_file, candidate.source_root),
            "source_file_sha256": source_file_hash,
            "source_row": candidate.source_row,
            "source_id": candidate.source_id,
            "variant": candidate.variant,
            **metadata,
        },
        "hashes": {
            "query_sha256": _sha256_bytes(candidate.query.encode("utf-8")),
            "normalized_query_sha256": _sha256_bytes(normalized_query.encode("utf-8")),
            "decontamination_sha256": _sha256_bytes(_guard_value(candidate).encode("utf-8")),
            "content_sha256": content_hash,
        },
    }


def _write_jsonl(path: Path, rows: Sequence[Mapping[str, Any]]) -> str:
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True, ensure_ascii=False, separators=(",", ":")) + "\n")
    return sha256_file(path)


def _track_summary(path: Path, rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    return {
        "path": path.name,
        "rows": len(rows),
        "sha256": sha256_file(path),
        "sources": dict(sorted(Counter(str(row["source"]) for row in rows).items())),
        "modalities": dict(sorted(Counter(str(row["modality"]) for row in rows).items())),
        "safety_labels": dict(sorted(Counter(str(row["safety_label"]) for row in rows).items())),
        "canonical_categories": sorted({str(row["canonical_category"]) for row in rows}),
        "missing_media": sum(
            1 for row in rows for item in row.get("media", []) if not item.get("available", False)
        ),
    }


def build_public_benchmark_pack(
    source_root: str | Path,
    output_dir: str | Path,
    *,
    roots: Mapping[str, str | Path] | None = None,
    revisions: Mapping[str, str] | None = None,
    allow_missing: bool = False,
    near_threshold: float = 0.92,
    quick_limit: int = 200,
    salad_warm_per_category: int = 10,
    require_media: bool = False,
) -> BuildResult:
    """Normalize local official datasets and build eval-first decontaminated tracks."""
    if quick_limit < 1:
        raise ValueError("quick_limit must be >= 1")
    if salad_warm_per_category < 1:
        raise ValueError("salad_warm_per_category must be >= 1")
    source_root_path = Path(source_root).expanduser().resolve()
    located = locate_dataset_roots(source_root_path, roots, allow_missing=allow_missing)
    candidates = load_candidates(located, salad_warm_per_category=salad_warm_per_category)
    raw_counts = dict(sorted(Counter(candidate.dataset for candidate in candidates).items()))
    retained, dedup_stats = deduplicate_candidates(candidates, near_threshold=near_threshold)

    input_file_datasets = {candidate.source_file: candidate.dataset for candidate in candidates}
    tiny_selection = located.get("mm_safetybench", Path("/nonexistent")) / "TinyVersion_ID_List.json"
    if tiny_selection.is_file():
        input_file_datasets[tiny_selection] = "mm_safetybench"
    source_hashes = {path: sha256_file(path) for path in sorted(input_file_datasets)}
    revision_overrides = dict(revisions or {})
    unknown_revisions = sorted(set(revision_overrides) - set(located))
    if unknown_revisions:
        raise ValueError(f"revision override has no located dataset: {', '.join(unknown_revisions)}")
    resolved_revisions = {
        name: revision_overrides.get(name) or _revision(path)
        for name, path in located.items()
    }
    rows_by_track: dict[str, list[dict[str, Any]]] = {track: [] for track in PRIMARY_TRACKS}
    quick_ids: set[str] = set()
    quick_fallback: list[dict[str, Any]] = []
    for candidate in sorted(retained, key=_candidate_key):
        row = _candidate_to_row(candidate, source_hashes[candidate.source_file], resolved_revisions.get(candidate.dataset))
        rows_by_track[candidate.track].append(row)
        if candidate.track == "sealed_eval_text" and candidate.dataset in {"strongreject", "jailbreakbench"}:
            quick_fallback.append(row)
            if candidate.quick:
                quick_ids.add(str(row["id"]))

    for rows in rows_by_track.values():
        rows.sort(key=lambda row: (str(row["source"]), str(row["id"])))
    quick_rows = [row for row in quick_fallback if str(row["id"]) in quick_ids]
    if not quick_rows:
        quick_rows = sorted(quick_fallback, key=lambda row: str(row["hashes"]["content_sha256"]))
    quick_rows = quick_rows[:quick_limit]
    quick_rows.sort(key=lambda row: (str(row["source"]), str(row["id"])))

    missing_media = [
        item for row in rows_by_track["sealed_eval_vlm"] for item in row["media"] if not item["available"]
    ]
    if require_media and missing_media:
        raise FileNotFoundError(f"{len(missing_media)} referenced evaluation images are missing")

    output = Path(output_dir).expanduser().resolve()
    if output.exists() and any(output.iterdir()):
        raise FileExistsError(f"refusing to overwrite non-empty output directory: {output}")
    output.mkdir(parents=True, exist_ok=True)
    for track in PRIMARY_TRACKS:
        _write_jsonl(output / OUTPUT_FILENAMES[track], rows_by_track[track])
    _write_jsonl(output / QUICK_EVAL_FILENAME, quick_rows)

    all_primary_rows = [row for track in PRIMARY_TRACKS for row in rows_by_track[track]]
    canonical_categories = sorted({str(row["canonical_category"]) for row in all_primary_rows})
    source_files = []
    for path, digest in sorted(source_hashes.items(), key=lambda item: str(item[0])):
        dataset = input_file_datasets[path]
        source_files.append({
            "dataset": dataset,
            "path": _relative(path, located[dataset]),
            "sha256": digest,
            "role": "selection" if path == tiny_selection else "records",
        })
    tracks = {
        track: _track_summary(output / OUTPUT_FILENAMES[track], rows_by_track[track])
        for track in PRIMARY_TRACKS
    }
    tracks["sealed_eval_quick"] = {
        **_track_summary(output / QUICK_EVAL_FILENAME, quick_rows),
        "view_of": "sealed_eval_text",
        "selection": "StrongREJECT-small and JBB Original when available; deterministic StrongREJECT/JBB fallback",
        "limit": quick_limit,
    }
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "builder": "defense_arena.public_datasets",
        "protocol": {
            "priority": ["sealed_eval_text", "sealed_eval_vlm", "benign_eval", "defender_train", "memory_warm"],
            "exact_normalization": "Unicode NFKC, casefold, punctuation/symbol/space collapse",
            "near_duplicate_threshold": near_threshold,
            "eval_first_decontamination": True,
            "near_duplicate_scope": "evaluation and benign tracks are mutually de-duplicated; all train/warm candidates are checked against the frozen evaluation index; exact duplicate removal is global",
            "multimodal_variant_policy": "retain official MM-SafetyBench image variants; use their base text as a train/warm contamination guard",
            "salad_warm_selection": {
                "source_file": "base_set.json",
                "leaf_category_cap": salad_warm_per_category,
                "priority": "source=self-instructed first, then deterministic decontamination-text hash",
                "enhanced_sets": "attack_enhanced_set and defense_enhanced_set are defender_train only",
            },
        },
        "datasets": {
            name: {
                "upstream": SPECS_BY_NAME[name].upstream,
                "license": SPECS_BY_NAME[name].license,
                "root": _relative(path, source_root_path),
                "revision": resolved_revisions.get(name),
                "normalized_candidates_after_source_selection": raw_counts.get(name, 0),
            }
            for name, path in sorted(located.items())
        },
        "source_files": source_files,
        "deduplication": dedup_stats,
        "canonical_categories": {
            "count": len(canonical_categories),
            "values": canonical_categories,
        },
        "tracks": tracks,
    }
    manifest_path = output / "manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return BuildResult(output_dir=output, manifest=manifest)


__all__ = [
    "DATASET_SPECS",
    "OUTPUT_FILENAMES",
    "PRIMARY_TRACKS",
    "QUICK_EVAL_FILENAME",
    "BuildResult",
    "build_public_benchmark_pack",
    "canonical_category",
    "deduplicate_candidates",
    "load_candidates",
    "locate_dataset_roots",
    "normalize_text",
]
