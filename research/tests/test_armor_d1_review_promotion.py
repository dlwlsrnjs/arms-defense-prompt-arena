from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

from defense_arena.armor_challenge_preflight import (
    build_d1_challenge_cohort,
    write_d1_challenge_cohort,
)
from defense_arena.armor_challenge_review import (
    build_reviewer_decision_artifact,
    canonical_sha256,
    generate_blinded_reviewer_packets,
    write_private_reviewer_decision_artifact,
)
from defense_arena.armor_d1_review_promotion import (
    CANONICAL_CATEGORIES,
    D1ReviewPromotion,
    D1ReviewPromotionError,
    PendingReviewCohortArtifacts,
    build_d1_review_promotion,
    write_d1_review_promotion,
)
from defense_arena.armor_d1_review_reselection import (
    D1ReviewReselectionError,
    build_d1_review_reselection,
    write_d1_review_reselection,
)
from defense_arena.memory_compiler import normalized_behavior_sha256


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _write_json(path: Path, value: object, *, mode: int = 0o600) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    path.chmod(mode)


def _row(
    *,
    cohort_label: str,
    text_namespace: str,
    category: str,
    position: int,
) -> dict:
    behavior_id = f"{cohort_label}-behavior-{position:02d}"
    text = f"PRIVATE-PROMOTION-SENTINEL {text_namespace} {category} {position % 2}"
    normalized = normalized_behavior_sha256(text)
    return {
        "schema_version": 1,
        "id": behavior_id,
        "behavior": text,
        "query": text,
        "safety_label": "harmful",
        "canonical_category": category,
        "risk_category": category,
        "source": "promotion-fixture",
        "source_split": "train",
        "track": "defender_train",
        "modality": "text",
        "hashes": {
            "content_sha256": _sha(f"content:{cohort_label}:{position}"),
            "normalized_query_sha256": normalized,
            "decontamination_sha256": normalized,
        },
    }


def _cohort(
    root: Path,
    cohort_label: str,
    *,
    text_namespace: str | None = None,
    reject_behavior_ids: set[str] | None = None,
    reject_categories: set[str] | None = None,
    include_target_outcomes: bool = False,
) -> dict:
    root.mkdir(parents=True)
    namespace = text_namespace or cohort_label
    rows: list[dict] = []
    position = 0
    for category in CANONICAL_CATEGORIES:
        for _ in range(2):
            rows.append(
                _row(
                    cohort_label=cohort_label,
                    text_namespace=namespace,
                    category=category,
                    position=position,
                )
            )
            if include_target_outcomes:
                rows[-1]["target_outcome"] = "forbidden synthetic outcome"
            position += 1
    dataset = root / "defender-train.jsonl"
    dataset.write_text(
        "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows),
        encoding="utf-8",
    )
    memory = root / "memory.json"
    memory.write_text("[]\n", encoding="utf-8")
    benchmark = root / "benchmark-manifest.json"
    benchmark.write_text('{"schema_version":1}\n', encoding="utf-8")
    selected, pending = build_d1_challenge_cohort(
        dataset,
        benchmark_manifest_path=benchmark,
        memory_path=memory,
        category_allowlist=CANONICAL_CATEGORIES,
        per_category=2,
        seed=37,
        target_call_budget=4,
    )
    cohort_root = root / "cohort"
    manifest = write_d1_challenge_cohort(cohort_root, selected, pending)
    manifest_path = cohort_root / "challenge_manifest.json"
    private_rows_path = Path(manifest["private_behavior_file"]["path"])

    packet_paths = (
        root / "packet-a.private.json",
        root / "packet-b.private.json",
    )
    packets = generate_blinded_reviewer_packets(
        pending_manifest_path=manifest_path,
        selected_behaviors_path=private_rows_path,
        reviewer_slots=(f"{cohort_label}-slot-a", f"{cohort_label}-slot-b"),
        output_paths=packet_paths,
    )
    by_text = {row["query"]: row for row in rows}
    decision_paths = (
        root / "decision-a.private.json",
        root / "decision-b.private.json",
    )
    decisions: list[dict] = []
    rejected = reject_behavior_ids or set()
    rejected_categories = reject_categories or set()
    for reviewer_index, (packet, path, kind) in enumerate(
        zip(packets, decision_paths, ("model", "human"), strict=True)
    ):
        values = {}
        for item in packet["items"]:
            row = by_text[item["behavior_text"]]
            should_reject = reviewer_index == 0 and (
                row["id"] in rejected
                or row["canonical_category"] in rejected_categories
            )
            values[item["review_item_id"]] = "reject" if should_reject else "approve"
        artifact = build_reviewer_decision_artifact(
            packet,
            reviewer_id=f"{cohort_label}-reviewer-{reviewer_index + 1}",
            reviewer_kind=kind,
            decisions=values,
        )
        write_private_reviewer_decision_artifact(path, artifact)
        decisions.append(artifact)

    artifacts = PendingReviewCohortArtifacts(
        pending_manifest_path=manifest_path,
        private_rows_path=private_rows_path,
        reviewer_packet_paths=packet_paths,
        reviewer_decision_paths=decision_paths,
    )
    return {
        "artifacts": artifacts,
        "rows": rows,
        "manifest": manifest,
        "manifest_path": manifest_path,
        "private_rows_path": private_rows_path,
        "packets": packets,
        "packet_paths": packet_paths,
        "decisions": decisions,
        "decision_paths": decision_paths,
    }


def _prior_final_review(
    root: Path,
    source_promotion: D1ReviewPromotion,
    *,
    reject_behavior_ids: set[str],
) -> dict:
    root.mkdir(parents=True)
    private_rows = list(source_promotion.private_rows)
    dataset = root / "promoted-source.private.jsonl"
    dataset.write_text(
        "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in private_rows),
        encoding="utf-8",
    )
    dataset.chmod(0o600)
    memory = root / "memory.json"
    memory.write_text("[]\n", encoding="utf-8")
    benchmark = root / "benchmark-manifest.json"
    benchmark.write_text('{"schema_version":1}\n', encoding="utf-8")
    selected, pending = build_d1_challenge_cohort(
        dataset,
        benchmark_manifest_path=benchmark,
        memory_path=memory,
        category_allowlist=CANONICAL_CATEGORIES,
        per_category=2,
        seed=41,
        target_call_budget=4,
    )
    cohort_root = root / "cohort"
    manifest = write_d1_challenge_cohort(cohort_root, selected, pending)
    manifest_path = cohort_root / "challenge_manifest.json"
    private_rows_path = Path(manifest["private_behavior_file"]["path"])
    packet_paths = (
        root / "packet-a.private.json",
        root / "packet-b.private.json",
    )
    packets = generate_blinded_reviewer_packets(
        pending_manifest_path=manifest_path,
        selected_behaviors_path=private_rows_path,
        reviewer_slots=("prior-final-slot-a", "prior-final-slot-b"),
        output_paths=packet_paths,
    )
    rows_by_text = {row["query"]: row for row in private_rows}
    decision_paths = (
        root / "decision-a.private.json",
        root / "decision-b.private.json",
    )
    decisions: list[dict] = []
    for reviewer_index, (packet, path, reviewer_kind) in enumerate(
        zip(packets, decision_paths, ("model", "human"), strict=True)
    ):
        values = {}
        for item in packet["items"]:
            behavior_id = rows_by_text[item["behavior_text"]]["id"]
            values[item["review_item_id"]] = (
                "reject"
                if reviewer_index == 0 and behavior_id in reject_behavior_ids
                else "approve"
            )
        decision = build_reviewer_decision_artifact(
            packet,
            reviewer_id=f"prior-final-reviewer-{reviewer_index + 1}",
            reviewer_kind=reviewer_kind,
            decisions=values,
        )
        write_private_reviewer_decision_artifact(path, decision)
        decisions.append(decision)
    return {
        "manifest": manifest,
        "manifest_path": manifest_path,
        "private_rows_path": private_rows_path,
        "packet_paths": packet_paths,
        "packets": packets,
        "decision_paths": decision_paths,
        "decisions": decisions,
    }


def _keys(value: object) -> set[str]:
    observed: set[str] = set()
    if isinstance(value, dict):
        for key, child in value.items():
            observed.add(str(key))
            observed.update(_keys(child))
    elif isinstance(value, list):
        for child in value:
            observed.update(_keys(child))
    return observed


def test_promotes_deterministic_two_per_category_and_writes_private_raw_rows(
    tmp_path: Path,
) -> None:
    first = _cohort(
        tmp_path / "first-with-reject",
        "first-reject",
        reject_behavior_ids={"first-reject-behavior-00"},
    )
    rejected_id = "first-reject-behavior-00"
    second = _cohort(tmp_path / "second", "second")

    promotion = build_d1_review_promotion(
        [first["artifacts"], second["artifacts"]],
        ranking_seed=20261101,
    )
    reversed_promotion = build_d1_review_promotion(
        [second["artifacts"], first["artifacts"]],
        ranking_seed=20261101,
    )

    assert promotion.manifest == reversed_promotion.manifest
    assert promotion.private_rows == reversed_promotion.private_rows
    assert promotion.manifest["target_outcomes_used"] is False
    assert promotion.manifest["aggregate"]["selected_count"] == 16
    assert promotion.manifest["aggregate"]["category_selected_counts"] == {
        category: 2 for category in CANONICAL_CATEGORIES
    }
    assert rejected_id not in {
        candidate["behavior_id"]
        for candidate in promotion.manifest["selected_candidates"]
    }
    assert promotion.manifest["manifest_sha256"] == canonical_sha256(
        {
            key: value
            for key, value in promotion.manifest.items()
            if key != "manifest_sha256"
        }
    )
    assert "decision" not in _keys(promotion.manifest)
    assert "decisions" not in _keys(promotion.manifest)
    assert "reviewer_id" not in _keys(promotion.manifest)
    serialized_public = json.dumps(promotion.manifest, ensure_ascii=False)
    assert "PRIVATE-PROMOTION-SENTINEL" not in serialized_public
    assert "first-reject-reviewer" not in serialized_public
    assert all(
        len(source["reviewer_packet_sha256"]) == 2
        and len(source["reviewer_decision_artifact_sha256"]) == 2
        for source in promotion.manifest["source_cohorts"]
    )

    private_output = tmp_path / "promoted.private.jsonl"
    manifest_output = tmp_path / "promotion.json"
    written_private, written_manifest = write_d1_review_promotion(
        promotion,
        private_rows_output_path=private_output,
        promotion_manifest_output_path=manifest_output,
    )
    assert written_private == private_output
    assert written_manifest == manifest_output
    assert private_output.stat().st_mode & 0o777 == 0o600
    assert manifest_output.stat().st_mode & 0o777 == 0o644
    private_rows = [
        json.loads(line)
        for line in private_output.read_text(encoding="utf-8").splitlines()
    ]
    assert private_rows == list(promotion.private_rows)
    assert json.loads(manifest_output.read_text()) == promotion.manifest
    assert (
        _sha(private_output.read_text(encoding="utf-8"))
        == promotion.manifest["private_rows_artifact"]["file_sha256"]
    )

    before_private = private_output.read_bytes()
    before_manifest = manifest_output.read_bytes()
    with pytest.raises(D1ReviewPromotionError, match="overwrite"):
        write_d1_review_promotion(
            promotion,
            private_rows_output_path=private_output,
            promotion_manifest_output_path=manifest_output,
        )
    assert private_output.read_bytes() == before_private
    assert manifest_output.read_bytes() == before_manifest


def test_insufficient_unanimous_category_approvals_fail_closed(tmp_path: Path) -> None:
    first = _cohort(
        tmp_path / "first",
        "first",
        reject_categories={CANONICAL_CATEGORIES[0]},
    )
    second = _cohort(
        tmp_path / "second",
        "second",
        reject_categories={CANONICAL_CATEGORIES[0]},
    )

    with pytest.raises(D1ReviewPromotionError, match="insufficient unanimous"):
        build_d1_review_promotion(
            [first["artifacts"], second["artifacts"]],
            ranking_seed=1,
        )


@pytest.mark.parametrize("artifact", ["manifest", "row", "packet", "decision"])
def test_input_self_hash_or_file_binding_tamper_is_rejected(
    tmp_path: Path,
    artifact: str,
) -> None:
    fixture = _cohort(tmp_path / artifact, artifact)
    if artifact == "manifest":
        value = json.loads(fixture["manifest_path"].read_text())
        value["selection_policy"]["seed"] += 1
        _write_json(fixture["manifest_path"], value, mode=0o644)
    elif artifact == "row":
        rows = fixture["private_rows_path"].read_text().splitlines()
        value = json.loads(rows[0])
        value["query"] += " tampered"
        rows[0] = json.dumps(value)
        fixture["private_rows_path"].write_text("\n".join(rows) + "\n")
        fixture["private_rows_path"].chmod(0o600)
    elif artifact == "packet":
        value = json.loads(fixture["packet_paths"][0].read_text())
        value["items"][0]["behavior_text"] += " tampered"
        _write_json(fixture["packet_paths"][0], value)
    else:
        value = json.loads(fixture["decision_paths"][0].read_text())
        value["decisions"][0]["decision"] = "reject"
        _write_json(fixture["decision_paths"][0], value)

    with pytest.raises(D1ReviewPromotionError):
        build_d1_review_promotion([fixture["artifacts"]], ranking_seed=3)


def test_self_hashed_but_noncanonical_packet_mapping_is_rejected(
    tmp_path: Path,
) -> None:
    fixture = _cohort(tmp_path / "cohort", "cohort")
    packet = json.loads(fixture["packet_paths"][0].read_text())
    packet["items"][0]["behavior_text"] += " changed"
    payload = {
        "behavior_text": packet["items"][0]["behavior_text"],
        "category": packet["items"][0]["category"],
        "modality": packet["items"][0]["modality"],
    }
    packet["items"][0]["review_payload_sha256"] = canonical_sha256(payload)
    packet.pop("packet_sha256")
    packet["packet_sha256"] = canonical_sha256(packet)
    _write_json(fixture["packet_paths"][0], packet)

    with pytest.raises(D1ReviewPromotionError, match="exactly match"):
        build_d1_review_promotion([fixture["artifacts"]], ranking_seed=3)


@pytest.mark.parametrize("mutation", ["same_id", "invalid_kind"])
def test_reviewers_require_distinct_ids_and_explicit_valid_kinds(
    tmp_path: Path,
    mutation: str,
) -> None:
    fixture = _cohort(tmp_path / mutation, mutation)
    first = fixture["decisions"][0]
    second = copy.deepcopy(fixture["decisions"][1])
    if mutation == "same_id":
        second["reviewer_id"] = first["reviewer_id"]
        expected = "identities must be distinct"
    else:
        second["reviewer_kind"] = "committee"
        expected = "reviewer_kind"
    second.pop("decision_artifact_sha256")
    second["decision_artifact_sha256"] = canonical_sha256(second)
    _write_json(fixture["decision_paths"][1], second)

    with pytest.raises(D1ReviewPromotionError, match=expected):
        build_d1_review_promotion([fixture["artifacts"]], ranking_seed=3)


def test_duplicate_cohort_or_candidate_hash_across_cohorts_is_rejected(
    tmp_path: Path,
) -> None:
    first = _cohort(tmp_path / "first", "first")
    with pytest.raises(D1ReviewPromotionError, match="duplicate source"):
        build_d1_review_promotion(
            [first["artifacts"], first["artifacts"]],
            ranking_seed=5,
        )

    shared_a = _cohort(
        tmp_path / "shared-a",
        "shared-a",
        text_namespace="shared-text",
    )
    shared_b = _cohort(
        tmp_path / "shared-b",
        "shared-b",
        text_namespace="shared-text",
    )
    with pytest.raises(D1ReviewPromotionError, match="normalized_query_sha256"):
        build_d1_review_promotion(
            [shared_a["artifacts"], shared_b["artifacts"]],
            ranking_seed=5,
        )


def test_nonprivate_input_and_preexisting_public_output_fail_without_partial_write(
    tmp_path: Path,
) -> None:
    fixture = _cohort(tmp_path / "cohort", "cohort")
    fixture["packet_paths"][0].chmod(0o644)
    with pytest.raises(D1ReviewPromotionError, match="mode 0600"):
        build_d1_review_promotion([fixture["artifacts"]], ranking_seed=7)

    fixture["packet_paths"][0].chmod(0o600)
    promotion = build_d1_review_promotion([fixture["artifacts"]], ranking_seed=7)
    private_output = tmp_path / "must-not-exist.private.jsonl"
    manifest_output = tmp_path / "already-exists.json"
    manifest_output.write_text("preserve me", encoding="utf-8")
    with pytest.raises(D1ReviewPromotionError, match="overwrite"):
        write_d1_review_promotion(
            promotion,
            private_rows_output_path=private_output,
            promotion_manifest_output_path=manifest_output,
        )
    assert not private_output.exists()
    assert manifest_output.read_text() == "preserve me"


def test_target_outcome_use_attestation_is_required(tmp_path: Path) -> None:
    fixture = _cohort(tmp_path / "cohort", "cohort")
    manifest = json.loads(fixture["manifest_path"].read_text())
    manifest["selection_policy"]["no_target_outcome_used"] = False
    manifest.pop("manifest_sha256")
    manifest["manifest_sha256"] = canonical_sha256(manifest)
    _write_json(fixture["manifest_path"], manifest, mode=0o644)

    with pytest.raises(D1ReviewPromotionError, match="outcome-blind"):
        build_d1_review_promotion([fixture["artifacts"]], ranking_seed=9)


def test_private_rows_must_not_carry_target_outcomes(tmp_path: Path) -> None:
    fixture = _cohort(
        tmp_path / "cohort-with-outcomes",
        "cohort-with-outcomes",
        include_target_outcomes=True,
    )

    with pytest.raises(D1ReviewPromotionError, match="target-outcome field"):
        build_d1_review_promotion([fixture["artifacts"]], ranking_seed=9)


def test_reselection_uses_smallest_seed_and_writes_raw_free_attestation(
    tmp_path: Path,
) -> None:
    first = _cohort(tmp_path / "source-first", "source-first")
    second = _cohort(tmp_path / "source-second", "source-second")
    sources = [first["artifacts"], second["artifacts"]]
    start_seed = 11
    prior_promotion = build_d1_review_promotion(sources, ranking_seed=start_seed)
    rejected_id = prior_promotion.manifest["selected_candidates"][0]["behavior_id"]
    rejected_category = prior_promotion.manifest["selected_candidates"][0]["category"]
    prior = _prior_final_review(
        tmp_path / "prior-final",
        prior_promotion,
        reject_behavior_ids={rejected_id},
    )

    expected_seed = start_seed
    while True:
        candidate = build_d1_review_promotion(sources, ranking_seed=expected_seed)
        selected_ids = {
            row["behavior_id"] for row in candidate.manifest["selected_candidates"]
        }
        if rejected_id not in selected_ids:
            break
        expected_seed += 1

    with pytest.raises(D1ReviewReselectionError, match="seed search exhausted"):
        build_d1_review_reselection(
            sources,
            prior_pending_manifest_path=prior["manifest_path"],
            prior_private_rows_path=prior["private_rows_path"],
            prior_reviewer_packet_paths=prior["packet_paths"],
            prior_reviewer_decision_paths=prior["decision_paths"],
            ranking_seed_start=start_seed,
            max_seed_attempts=1,
        )

    reselection = build_d1_review_reselection(
        sources,
        prior_pending_manifest_path=prior["manifest_path"],
        prior_private_rows_path=prior["private_rows_path"],
        prior_reviewer_packet_paths=prior["packet_paths"],
        prior_reviewer_decision_paths=prior["decision_paths"],
        ranking_seed_start=start_seed,
    )
    reversed_reselection = build_d1_review_reselection(
        list(reversed(sources)),
        prior_pending_manifest_path=prior["manifest_path"],
        prior_private_rows_path=prior["private_rows_path"],
        prior_reviewer_packet_paths=tuple(reversed(prior["packet_paths"])),
        prior_reviewer_decision_paths=tuple(reversed(prior["decision_paths"])),
        ranking_seed_start=start_seed,
    )

    assert reselection.promotion == reversed_reselection.promotion
    assert reselection.attestation == reversed_reselection.attestation
    assert reselection.attestation["target_outcomes_used"] is False
    assert reselection.attestation["seed_search"] == {
        "policy": "ascending_integer_first_match",
        "start_seed": start_seed,
        "chosen_seed": expected_seed,
        "examined_seed_count": expected_seed - start_seed + 1,
    }
    rejection_summary = reselection.attestation["rejection_summary"]
    assert rejection_summary == {
        "rejected_count": 1,
        "category_rejected_counts": {
            category: int(category == rejected_category)
            for category in CANONICAL_CATEGORIES
        },
    }
    assert "rejected_behavior_ids_sha256" not in rejection_summary
    assert "rejected_behavior_ids_hash_policy" not in rejection_summary
    selected_ids = {
        row["behavior_id"]
        for row in reselection.promotion.manifest["selected_candidates"]
    }
    assert rejected_id not in selected_ids
    assert (
        reselection.attestation["new_promotion_manifest_sha256"]
        == reselection.promotion.manifest["manifest_sha256"]
    )
    unhashed = dict(reselection.attestation)
    attestation_sha256 = unhashed.pop("attestation_sha256")
    assert attestation_sha256 == canonical_sha256(unhashed)
    prior_review = reselection.attestation["prior_final_review"]
    assert prior_review == {
        "challenge_manifest_sha256": prior["manifest"]["manifest_sha256"],
        "private_rows_file_sha256": prior["manifest"]["private_behavior_file"][
            "sha256"
        ],
        "reviewer_packet_sha256": sorted(
            packet["packet_sha256"] for packet in prior["packets"]
        ),
        "reviewer_decision_artifact_sha256": sorted(
            decision["decision_artifact_sha256"] for decision in prior["decisions"]
        ),
    }
    serialized = json.dumps(reselection.attestation, ensure_ascii=False)
    assert rejected_id not in serialized
    assert "PRIVATE-PROMOTION-SENTINEL" not in serialized
    assert "prior-final-reviewer" not in serialized
    assert "decisions" not in _keys(reselection.attestation)
    assert "reviewer_id" not in _keys(reselection.attestation)

    private_output = tmp_path / "out" / "promoted.private.jsonl"
    manifest_output = tmp_path / "out" / "promotion.json"
    attestation_output = tmp_path / "out" / "reselection.json"
    written = write_d1_review_reselection(
        reselection,
        private_rows_output_path=private_output,
        promotion_manifest_output_path=manifest_output,
        reselection_attestation_output_path=attestation_output,
    )
    assert written == (private_output, manifest_output, attestation_output)
    assert private_output.stat().st_mode & 0o777 == 0o600
    assert manifest_output.stat().st_mode & 0o777 == 0o644
    assert attestation_output.stat().st_mode & 0o777 == 0o644
    assert json.loads(manifest_output.read_text()) == reselection.promotion.manifest
    assert json.loads(attestation_output.read_text()) == reselection.attestation
    with pytest.raises(D1ReviewReselectionError, match="overwrite"):
        write_d1_review_reselection(
            reselection,
            private_rows_output_path=private_output,
            promotion_manifest_output_path=manifest_output,
            reselection_attestation_output_path=attestation_output,
        )

    blocked_private = tmp_path / "blocked" / "promoted.private.jsonl"
    blocked_manifest = tmp_path / "blocked" / "promotion.json"
    blocked_attestation = tmp_path / "blocked" / "reselection.json"
    blocked_attestation.parent.mkdir()
    blocked_attestation.write_text("preserve me\n", encoding="utf-8")
    with pytest.raises(D1ReviewReselectionError, match="overwrite"):
        write_d1_review_reselection(
            reselection,
            private_rows_output_path=blocked_private,
            promotion_manifest_output_path=blocked_manifest,
            reselection_attestation_output_path=blocked_attestation,
        )
    assert not blocked_private.exists()
    assert not blocked_manifest.exists()
    assert blocked_attestation.read_text() == "preserve me\n"


def test_reselection_fails_closed_when_no_replacement_or_search_is_exhausted(
    tmp_path: Path,
) -> None:
    first = _cohort(tmp_path / "source", "source")
    sources = [first["artifacts"]]
    start_seed = 19
    prior_promotion = build_d1_review_promotion(sources, ranking_seed=start_seed)
    rejected_id = prior_promotion.manifest["selected_candidates"][0]["behavior_id"]
    prior = _prior_final_review(
        tmp_path / "prior-final",
        prior_promotion,
        reject_behavior_ids={rejected_id},
    )

    with pytest.raises(D1ReviewReselectionError, match="no feasible"):
        build_d1_review_reselection(
            sources,
            prior_pending_manifest_path=prior["manifest_path"],
            prior_private_rows_path=prior["private_rows_path"],
            prior_reviewer_packet_paths=prior["packet_paths"],
            prior_reviewer_decision_paths=prior["decision_paths"],
            ranking_seed_start=start_seed,
            max_seed_attempts=1,
        )


def test_reselection_rejects_prior_candidate_outside_original_pool(
    tmp_path: Path,
) -> None:
    first = _cohort(tmp_path / "source-first", "source-first")
    second = _cohort(tmp_path / "source-second", "source-second")
    outside = _cohort(
        tmp_path / "outside",
        "outside",
        reject_behavior_ids={"outside-behavior-00"},
    )

    with pytest.raises(D1ReviewReselectionError, match="absent from the original"):
        build_d1_review_reselection(
            [first["artifacts"], second["artifacts"]],
            prior_pending_manifest_path=outside["manifest_path"],
            prior_private_rows_path=outside["private_rows_path"],
            prior_reviewer_packet_paths=outside["packet_paths"],
            prior_reviewer_decision_paths=outside["decision_paths"],
            ranking_seed_start=0,
        )


def test_reselection_rejects_tampered_prior_review_before_output(
    tmp_path: Path,
) -> None:
    first = _cohort(tmp_path / "source-first", "source-first")
    second = _cohort(tmp_path / "source-second", "source-second")
    sources = [first["artifacts"], second["artifacts"]]
    prior_promotion = build_d1_review_promotion(sources, ranking_seed=23)
    rejected_id = prior_promotion.manifest["selected_candidates"][0]["behavior_id"]
    prior = _prior_final_review(
        tmp_path / "prior-final",
        prior_promotion,
        reject_behavior_ids={rejected_id},
    )
    packet = json.loads(prior["packet_paths"][0].read_text())
    packet["items"][0]["behavior_text"] += " tampered"
    _write_json(prior["packet_paths"][0], packet)

    with pytest.raises(D1ReviewReselectionError):
        build_d1_review_reselection(
            sources,
            prior_pending_manifest_path=prior["manifest_path"],
            prior_private_rows_path=prior["private_rows_path"],
            prior_reviewer_packet_paths=prior["packet_paths"],
            prior_reviewer_decision_paths=prior["decision_paths"],
            ranking_seed_start=23,
        )
