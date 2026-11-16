from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).parents[1]
REPO = ROOT.parent
TAXONOMY_PATH = ROOT / "configs" / "aamd_rcat7_taxonomy_v1_1.json"
MANIFEST_PATH = ROOT / "configs" / "aamd_rcat7_taxonomy_v1_1.manifest.json"
LABELER_PATH = ROOT / "configs" / "aamd_llm_first_labeler_32b_v3.json"
PROTOCOL_PATH = ROOT / "configs" / "aamd_human_review_protocol_v3.json"
PROMPT_PATH = ROOT / "prompts" / "aamd_llm_first_labeler_32b_v3.txt"
WORKER_PATH = REPO / "aamd-human-workspace-site" / "worker" / "index.js"
FIXTURE_PATH = REPO / "aamd-human-workspace-site" / "fixtures" / "pilot-bundle.taxonomy-v3.synthetic.json"


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def codes(axis: dict) -> set[str]:
    return {
        entry if isinstance(entry, str) else entry["code"]
        for entry in axis["codes"]
    }


def test_taxonomy_manifest_and_cross_artifact_hashes_are_exact() -> None:
    taxonomy = load(TAXONOMY_PATH)
    manifest = load(MANIFEST_PATH)
    labeler = load(LABELER_PATH)
    protocol = load(PROTOCOL_PATH)
    fixture = load(FIXTURE_PATH)

    payload = canonical_bytes(taxonomy)
    digest = hashlib.sha256(payload).hexdigest()
    assert digest == "2f8512333c90888aa640e8432ec262cdd452adbae3d1e8df5c96c5654a5c816c"
    assert manifest["canonical_sha256"] == digest
    assert manifest["canonical_byte_length"] == len(payload)
    assert taxonomy["taxonomy_id"] == manifest["taxonomy_id"] == "aamd-rcat-7-v1.1"
    assert taxonomy["taxonomy_version"] == manifest["taxonomy_version"] == "1.1.0"

    prompt_hash = hashlib.sha256(PROMPT_PATH.read_bytes()).hexdigest()
    decoding_hash = hashlib.sha256(canonical_bytes(labeler["decoding"])).hexdigest()
    assert prompt_hash == labeler["prompt"]["sha256"]
    assert decoding_hash == labeler["decoding_config_sha256"]
    assert labeler["taxonomy"]["sha256"] == digest
    assert protocol["proposal_contract"]["first_pass_labeler"]["taxonomy_hash"] == digest
    assert protocol["proposal_contract"]["first_pass_labeler"]["prompt_template_hash"] == prompt_hash
    assert protocol["proposal_contract"]["first_pass_labeler"]["decoding_config_hash"] == decoding_hash
    assert fixture["tasks"][0]["taxonomy_hash"] == digest
    assert fixture["tasks"][0]["llm_proposal"]["provenance"]["taxonomy_hash"] == digest


def test_rcat7_is_detailed_multi_axis_and_not_attack_name_taxonomy() -> None:
    taxonomy = load(TAXONOMY_PATH)
    labeler = load(LABELER_PATH)
    protocol = load(PROTOCOL_PATH)
    sentinels = {"none", "uncertain", "unmapped"}

    mechanism_codes = {entry["code"] for entry in taxonomy["mechanisms"]}
    assert len(mechanism_codes) == 7
    assert all(code.startswith("RCAT7.MECHANISM.") for code in mechanism_codes)
    assert "classify attack method names" in taxonomy["non_goals"]

    expected_counts = {
        "consumed_response_signal": 10,
        "search_action": 4,
        "semantic_linkage": 2,
        "memory_source_scope": 6,
        "memory_operation": 5,
        "evidence_provenance": 3,
        "dialogue_horizon": 5,
    }
    for axis, expected in expected_counts.items():
        axis_codes = codes(taxonomy["orthogonal_axes"][axis])
        assert sentinels <= axis_codes
        assert len(axis_codes - sentinels) == expected
        assert taxonomy["orthogonal_axes"][axis]["cardinality"] == "exactly_one"

    required_axes = [
        "adaptation_mechanism",
        "consumed_response_signal",
        "search_action",
        "semantic_linkage",
        "memory_source_scope",
        "memory_operation",
        "evidence_provenance",
        "dialogue_horizon",
    ]
    assert labeler["taxonomy"]["required_axes"] == required_axes
    assert labeler["taxonomy"]["human_reviewed_axes"] == required_axes[:4]
    assert labeler["taxonomy"]["runtime_locked_axes"] == required_axes[4:]
    assert protocol["taxonomy_contract"]["human_reviewed_axes"] == required_axes[:4]
    assert protocol["taxonomy_contract"]["runtime_locked_axes"] == required_axes[4:]
    assert labeler["taxonomy"]["one_code_per_axis"] is True
    assert protocol["taxonomy_contract"]["one_code_per_reviewed_axis"] is True
    assert taxonomy["annotation_contract"]["secondary_mechanism_policy"].startswith("not_collected_in_v1")


def test_worker_registry_and_fixture_cover_the_frozen_taxonomy() -> None:
    taxonomy = load(TAXONOMY_PATH)
    fixture = load(FIXTURE_PATH)
    worker = WORKER_PATH.read_text(encoding="utf-8")

    all_codes = {entry["code"] for entry in taxonomy["mechanisms"]}
    for axis_name in [
        "consumed_response_signal",
        "search_action",
        "semantic_linkage",
        "memory_source_scope",
        "memory_operation",
        "evidence_provenance",
        "dialogue_horizon",
    ]:
        all_codes.update(codes(taxonomy["orthogonal_axes"][axis_name]) - {"none", "uncertain", "unmapped"})
    confounds = {
        confound["code"]
        for mechanism in taxonomy["mechanisms"]
        for confound in mechanism["benign_confounds"]
    }
    for code in all_codes | confounds:
        assert code in worker

    proposal = fixture["tasks"][0]["llm_proposal"]
    assert len(proposal["reviewed_axes"]) == 4
    assert {entry["axis"] for entry in proposal["reviewed_axes"]} == {
        "adaptation_mechanism",
        "consumed_response_signal",
        "search_action",
        "semantic_linkage",
    }
    assert all(entry["evidence_handles"] for entry in proposal["reviewed_axes"])
    assert set(fixture["tasks"][0]["locked_axes"]) == {
        "memory_source_scope",
        "memory_operation",
        "evidence_provenance",
        "dialogue_horizon",
    }
    assert proposal["benign_confound"]["evidence_handles"]
