from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from defense_arena.armor_challenge_preflight import (
    build_d1_challenge_cohort,
    write_d1_challenge_cohort,
)
from defense_arena.armor_challenge_review import (
    APPROVED_REVIEW_STATUS,
    ATTESTED_CASSETTE_STATUS,
    READY_STATUS,
    ChallengeReviewError,
    build_reviewer_decision_artifact,
    canonical_sha256,
    finalize_challenge_manifest,
    generate_blinded_reviewer_packets,
    write_private_reviewer_decision_artifact,
)
from defense_arena.armor_first_move_cassette import (
    FrozenFirstMoveCassette,
    FrozenFirstMoveCassetteBundle,
)
from defense_arena.memory_compiler import normalized_behavior_sha256


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _write_json(path: Path, value: object, *, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    path.chmod(mode)


def _row(index: int) -> dict:
    category = "A" if index < 8 else "B"
    behavior_id = f"behavior-{index:02d}"
    text = f"Private synthetic review behavior sentinel {index:02d}"
    normalized = normalized_behavior_sha256(text)
    return {
        "schema_version": 1,
        "id": behavior_id,
        "behavior": text,
        "query": text,
        "safety_label": "harmful",
        "canonical_category": category,
        "risk_category": category,
        "source": "review-fixture",
        "source_split": "train",
        "track": "defender_train",
        "modality": "text",
        "hashes": {
            "content_sha256": _sha(f"content:{behavior_id}"),
            "normalized_query_sha256": normalized,
            "decontamination_sha256": normalized,
        },
    }


def _pending_fixture(tmp_path: Path):
    tmp_path.mkdir(parents=True, exist_ok=True)
    rows = [_row(index) for index in range(16)]
    dataset = tmp_path / "defender-train.jsonl"
    dataset.write_text(
        "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows),
        encoding="utf-8",
    )
    memory = tmp_path / "memory.json"
    memory.write_text("[]\n", encoding="utf-8")
    benchmark = tmp_path / "benchmark-manifest.json"
    benchmark.write_text('{"schema_version":1}\n', encoding="utf-8")
    selected, pending = build_d1_challenge_cohort(
        dataset,
        benchmark_manifest_path=benchmark,
        memory_path=memory,
        category_allowlist=["A", "B"],
        per_category=8,
        seed=91,
        target_call_budget=4,
    )
    cohort = tmp_path / "cohort"
    finalized_pending = write_d1_challenge_cohort(cohort, selected, pending)
    manifest_path = cohort / "challenge_manifest.json"
    behaviors_path = Path(finalized_pending["private_behavior_file"]["path"])
    behaviors_path.chmod(0o600)

    cassettes = []
    for entry in finalized_pending["pairs"]:
        behavior_id = entry["behavior_id"]
        request = f"Private first request for {behavior_id}"
        cassettes.append(
            FrozenFirstMoveCassette(
                behavior_id=behavior_id,
                request_text=request,
                request_sha256=_sha(request),
                action_sha256=_sha(f"action:{behavior_id}"),
                image_assets=((f"asset:{behavior_id}", _sha(f"pixels:{behavior_id}")),),
            )
        )
    bundle = FrozenFirstMoveCassetteBundle(tuple(cassettes))
    bundle_path = tmp_path / "private-cassette-bundle.json"
    _write_json(bundle_path, bundle.to_dict())
    return {
        "rows": rows,
        "pending": finalized_pending,
        "manifest_path": manifest_path,
        "behaviors_path": behaviors_path,
        "bundle": bundle,
        "bundle_path": bundle_path,
    }


def _review_artifacts(tmp_path: Path, fixture, *, reject_first: bool = False):
    packet_paths = (
        tmp_path / "reviewer-a.private.json",
        tmp_path / "reviewer-b.private.json",
    )
    packets = generate_blinded_reviewer_packets(
        pending_manifest_path=fixture["manifest_path"],
        selected_behaviors_path=fixture["behaviors_path"],
        reviewer_slots=("reviewer-slot-a", "reviewer-slot-b"),
        output_paths=packet_paths,
    )
    decision_paths = (
        tmp_path / "decision-a.private.json",
        tmp_path / "decision-b.private.json",
    )
    reviewer_kinds = ("model", "human")
    decisions = []
    for index, (packet, path, reviewer_kind) in enumerate(
        zip(packets, decision_paths, reviewer_kinds, strict=True)
    ):
        values = {
            item["review_item_id"]: "approve" for item in packet["items"]
        }
        if reject_first and index == 0:
            values[packet["items"][0]["review_item_id"]] = "reject"
        artifact = build_reviewer_decision_artifact(
            packet,
            reviewer_id=f"reviewer-{index + 1}",
            reviewer_kind=reviewer_kind,
            decisions=values,
        )
        write_private_reviewer_decision_artifact(path, artifact)
        decisions.append(artifact)
    return packet_paths, packets, decision_paths, tuple(decisions)


def _without(value: dict, field: str) -> dict:
    copied = dict(value)
    copied.pop(field)
    return copied


def test_generates_two_private_blinded_packets_in_different_orders(tmp_path: Path):
    fixture = _pending_fixture(tmp_path)
    pending_before = fixture["manifest_path"].read_bytes()
    packet_paths = (tmp_path / "packet-a.json", tmp_path / "packet-b.json")

    packets = generate_blinded_reviewer_packets(
        pending_manifest_path=fixture["manifest_path"],
        selected_behaviors_path=fixture["behaviors_path"],
        reviewer_slots=("slot-a", "slot-b"),
        output_paths=packet_paths,
    )

    assert fixture["manifest_path"].read_bytes() == pending_before
    assert all(path.stat().st_mode & 0o777 == 0o600 for path in packet_paths)
    assert all(len(packet["items"]) == 16 for packet in packets)
    assert [item["behavior_text"] for item in packets[0]["items"]] != [
        item["behavior_text"] for item in packets[1]["items"]
    ]
    for packet in packets:
        assert packet["target_outcomes_included"] is False
        assert packet["pair_identifiers_included"] is False
        assert packet["packet_sha256"] == canonical_sha256(
            _without(packet, "packet_sha256")
        )
        assert all(
            not {"pair_id", "behavior_id", "attacker_seed"}.intersection(item)
            for item in packet["items"]
        )

    with pytest.raises(ChallengeReviewError, match="overwrite"):
        generate_blinded_reviewer_packets(
            pending_manifest_path=fixture["manifest_path"],
            selected_behaviors_path=fixture["behaviors_path"],
            reviewer_slots=("slot-a", "slot-b"),
            output_paths=packet_paths,
        )


def test_finalizes_only_after_two_approvals_and_exact_v2_cassette_coverage(
    tmp_path: Path,
):
    fixture = _pending_fixture(tmp_path)
    packet_paths, _packets, decision_paths, decisions = _review_artifacts(
        tmp_path, fixture
    )
    output = tmp_path / "challenge-manifest.execution-ready.json"

    finalized = finalize_challenge_manifest(
        pending_manifest_path=fixture["manifest_path"],
        selected_behaviors_path=fixture["behaviors_path"],
        reviewer_packet_paths=packet_paths,
        reviewer_decision_paths=decision_paths,
        cassette_bundle_path=fixture["bundle_path"],
        output_path=output,
    )

    assert finalized["status"] == READY_STATUS
    assert finalized["execution_eligible"] is True
    assert finalized["blocking_gates"] == []
    assert finalized["manifest_sha256"] == canonical_sha256(
        _without(finalized, "manifest_sha256")
    )
    cassette_hashes = {
        cassette.behavior_id: canonical_sha256(cassette.to_dict())
        for cassette in fixture["bundle"].cassettes
    }
    for entry in finalized["pairs"]:
        assert entry["compatibility_review"] == {
            "status": APPROVED_REVIEW_STATUS,
            "decision": "approve",
            "reviewer_kinds": ["model", "human"],
            "result_sha256": entry["compatibility_review"]["result_sha256"],
        }
        assert len(entry["compatibility_review"]["result_sha256"]) == 64
        assert entry["first_move_cassette"] == {
            "status": ATTESTED_CASSETTE_STATUS,
            "cassette_sha256": cassette_hashes[entry["behavior_id"]],
        }
        assert entry["challenge_entry_sha256"] == canonical_sha256(
            _without(entry, "challenge_entry_sha256")
        )
    assert [decision["reviewer_kind"] for decision in decisions] == [
        "model",
        "human",
    ]
    serialized = output.read_text(encoding="utf-8")
    assert all(row["query"] not in serialized for row in fixture["rows"])
    assert "reviewer-1" not in serialized
    assert fixture["pending"]["execution_eligible"] is False
    assert json.loads(fixture["manifest_path"].read_text())["execution_eligible"] is False

    before = output.read_bytes()
    with pytest.raises(ChallengeReviewError, match="overwrite"):
        finalize_challenge_manifest(
            pending_manifest_path=fixture["manifest_path"],
            selected_behaviors_path=fixture["behaviors_path"],
            reviewer_packet_paths=packet_paths,
            reviewer_decision_paths=decision_paths,
            cassette_bundle_path=fixture["bundle_path"],
            output_path=output,
        )
    assert output.read_bytes() == before


def test_reject_decision_blocks_finalization_and_preserves_reviewer_kind(
    tmp_path: Path,
):
    fixture = _pending_fixture(tmp_path)
    packet_paths, _packets, decision_paths, decisions = _review_artifacts(
        tmp_path,
        fixture,
        reject_first=True,
    )
    output = tmp_path / "must-not-finalize.json"

    assert decisions[0]["reviewer_kind"] == "model"
    with pytest.raises(ChallengeReviewError, match="rejected by a reviewer"):
        finalize_challenge_manifest(
            pending_manifest_path=fixture["manifest_path"],
            selected_behaviors_path=fixture["behaviors_path"],
            reviewer_packet_paths=packet_paths,
            reviewer_decision_paths=decision_paths,
            cassette_bundle_path=fixture["bundle_path"],
            output_path=output,
        )
    assert not output.exists()


def test_missing_decision_or_cassette_fails_closed(tmp_path: Path):
    fixture = _pending_fixture(tmp_path)
    packet_paths, _packets, decision_paths, decisions = _review_artifacts(
        tmp_path, fixture
    )

    incomplete = dict(decisions[0])
    incomplete["decisions"] = list(incomplete["decisions"][:-1])
    incomplete.pop("decision_artifact_sha256")
    incomplete["decision_artifact_sha256"] = canonical_sha256(incomplete)
    _write_json(decision_paths[0], incomplete)
    with pytest.raises(ChallengeReviewError, match="exactly 16 decisions"):
        finalize_challenge_manifest(
            pending_manifest_path=fixture["manifest_path"],
            selected_behaviors_path=fixture["behaviors_path"],
            reviewer_packet_paths=packet_paths,
            reviewer_decision_paths=decision_paths,
            cassette_bundle_path=fixture["bundle_path"],
            output_path=tmp_path / "missing-decision.json",
        )

    _write_json(decision_paths[0], decisions[0])
    missing_bundle = FrozenFirstMoveCassetteBundle(
        fixture["bundle"].cassettes[:-1]
    )
    _write_json(fixture["bundle_path"], missing_bundle.to_dict())
    with pytest.raises(ChallengeReviewError, match="exactly 16 cassettes"):
        finalize_challenge_manifest(
            pending_manifest_path=fixture["manifest_path"],
            selected_behaviors_path=fixture["behaviors_path"],
            reviewer_packet_paths=packet_paths,
            reviewer_decision_paths=decision_paths,
            cassette_bundle_path=fixture["bundle_path"],
            output_path=tmp_path / "missing-cassette.json",
        )


def test_hash_tamper_and_nonprivate_raw_artifact_fail_before_output(tmp_path: Path):
    fixture = _pending_fixture(tmp_path)
    tampered = json.loads(fixture["manifest_path"].read_text(encoding="utf-8"))
    tampered["pairs"][0]["category"] = "tampered"
    _write_json(fixture["manifest_path"], tampered, mode=0o644)

    with pytest.raises(ChallengeReviewError, match="self-hash mismatch"):
        generate_blinded_reviewer_packets(
            pending_manifest_path=fixture["manifest_path"],
            selected_behaviors_path=fixture["behaviors_path"],
            reviewer_slots=("a", "b"),
            output_paths=(tmp_path / "a.json", tmp_path / "b.json"),
        )

    fixture = _pending_fixture(tmp_path / "raw-field")
    injected = json.loads(fixture["manifest_path"].read_text(encoding="utf-8"))
    entry = injected["pairs"][0]
    entry["private_notes"] = fixture["rows"][0]["query"]
    entry["challenge_entry_sha256"] = canonical_sha256(
        _without(entry, "challenge_entry_sha256")
    )
    injected["manifest_sha256"] = canonical_sha256(
        _without(injected, "manifest_sha256")
    )
    _write_json(fixture["manifest_path"], injected, mode=0o644)
    with pytest.raises(ChallengeReviewError, match="fields mismatch"):
        generate_blinded_reviewer_packets(
            pending_manifest_path=fixture["manifest_path"],
            selected_behaviors_path=fixture["behaviors_path"],
            reviewer_slots=("a", "b"),
            output_paths=(tmp_path / "raw-a.json", tmp_path / "raw-b.json"),
        )

    fixture = _pending_fixture(tmp_path / "permissions")
    fixture["behaviors_path"].chmod(0o640)
    with pytest.raises(ChallengeReviewError, match="mode 0600"):
        generate_blinded_reviewer_packets(
            pending_manifest_path=fixture["manifest_path"],
            selected_behaviors_path=fixture["behaviors_path"],
            reviewer_slots=("a", "b"),
            output_paths=(tmp_path / "permissions-a.json", tmp_path / "permissions-b.json"),
        )


def test_reviewer_kind_must_be_explicit_human_or_model(tmp_path: Path):
    fixture = _pending_fixture(tmp_path)
    packets = generate_blinded_reviewer_packets(
        pending_manifest_path=fixture["manifest_path"],
        selected_behaviors_path=fixture["behaviors_path"],
        reviewer_slots=("a", "b"),
        output_paths=(tmp_path / "a.json", tmp_path / "b.json"),
    )
    decisions = {
        item["review_item_id"]: "approve" for item in packets[0]["items"]
    }

    with pytest.raises(ChallengeReviewError, match="human or model"):
        build_reviewer_decision_artifact(
            packets[0],
            reviewer_id="reviewer",
            reviewer_kind="unspecified",  # type: ignore[arg-type]
            decisions=decisions,
        )
