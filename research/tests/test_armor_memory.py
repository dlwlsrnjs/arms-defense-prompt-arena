from __future__ import annotations

from dataclasses import replace

from defense_arena.armor_memory import (
    build_memory_clause_pack,
    extract_failure_signals,
)
from defense_arena.memory_compiler import DefenseAtom


def _atom(family: str, priority: float, strategy: str) -> DefenseAtom:
    return DefenseAtom(
        id=f"atom-{family.replace('_', '-')}",
        family=family,
        modality="fixture",
        strategies=(strategy,),
        evidence_ids=(f"ev-{family}",),
        entries=10,
        successes=5,
        success_rate=0.5,
        mean_best_score=3.0,
        category_coverage=4,
        transition_evidence=2,
        mean_positive_gain=1.0,
        priority=priority,
        confidence="medium",
        invariant=f"Invariant for {family}.",
        forecast=f"Forecast for {family}.",
        likely_next_families=(),
        safe_action=f"Safe action for {family}.",
        benign_exception=f"Allow benign {family} tasks.",
        prompt_clause=f"Capability clause for {family}.",
        public_explanation="Broad boundary only.",
    )


def _audit() -> dict:
    return {
        "schema_version": 1,
        "comparisons": [
            {
                "label": "fixture",
                "all_cases": [
                    {
                        "behavior_id": "opaque-id",
                        "category": "Violence",
                        "movement": "new_strict_regression",
                        "candidate": {
                            "query_strategies": ["crescendo", "narrative"]
                        },
                    },
                    {
                        "behavior_id": "stable-id",
                        "category": "Privacy Violations",
                        "movement": "unchanged",
                        "candidate": {"query_strategies": ["email_thread"]},
                    },
                ],
            }
        ],
    }


def test_failure_signal_extraction_whitelists_regression_metadata():
    signals = extract_failure_signals(_audit())
    assert signals.regression_cases == 1
    assert signals.family_counts == (("adaptive_trajectory", 2),)
    assert signals.category_counts == (("Violence", 1),)
    assert signals.audit_sha256 is not None
    assert "opaque-id" not in str(signals.to_dict())


def test_matched_pack_uses_effectiveness_and_failure_feedback():
    atoms = [
        _atom("adaptive_trajectory", 0.50, "crescendo"),
        _atom("structured_transformation", 0.58, "flowchart"),
        _atom("social_document_framing", 0.40, "email_thread"),
    ]
    pack = build_memory_clause_pack(
        atoms,
        memory_sha256="1" * 64,
        memory_semantic_sha256="2" * 64,
        relation="matched",
        failure_audit=_audit(),
        max_atoms=2,
    )
    # The regression bonus promotes adaptive trajectory above the slightly
    # higher-frequency structured atom.
    assert pack.selected_atom_ids[0] == "atom-adaptive-trajectory"
    assert {clause.slot for clause in pack.clauses} == {
        "authority",
        "latent_capability",
        "output_audit",
        "safe_action",
        "disclosure",
    }
    serialized = str(pack.to_dict())
    assert "Capability clause for adaptive_trajectory" not in serialized
    assert pack.to_dict()["raw_attack_payload_included"] is False


def test_label_shuffled_pack_breaks_ranking_but_preserves_evidence_volume():
    atoms = [
        _atom("adaptive_trajectory", 0.70, "crescendo"),
        _atom("structured_transformation", 0.60, "flowchart"),
        _atom("social_document_framing", 0.50, "email_thread"),
        _atom("cross_modal_obfuscation", 0.40, "photographic"),
        _atom("fragmentation_and_many_shot", 0.30, "many_shot_mixup"),
    ]
    matched = build_memory_clause_pack(
        atoms,
        memory_sha256="3" * 64,
        memory_semantic_sha256="4" * 64,
        relation="matched",
        max_atoms=3,
    )
    shuffled = build_memory_clause_pack(
        atoms,
        memory_sha256="3" * 64,
        memory_semantic_sha256="4" * 64,
        relation="label_shuffled",
        max_atoms=3,
    )
    assert len(matched.selected_atom_ids) == len(shuffled.selected_atom_ids) == 3
    assert matched.selected_atom_ids != shuffled.selected_atom_ids
    assert set(matched.selected_atom_ids) != set(shuffled.selected_atom_ids)
    assert matched.memory_sha256 == shuffled.memory_sha256
    assert matched.compiler_memory_provenance_sha256 == matched.memory_sha256
    assert shuffled.compiler_memory_provenance_sha256 != shuffled.memory_sha256
    assert all(
        clause.provenance.attack_evidence_sha256
        for clause in shuffled.clauses
    )


def test_pack_is_deterministic_and_rejects_empty_evidence():
    atom = _atom("adaptive_trajectory", 0.7, "crescendo")
    kwargs = {
        "memory_sha256": "5" * 64,
        "memory_semantic_sha256": "6" * 64,
        "relation": "mismatched",
        "max_atoms": 1,
    }
    first = build_memory_clause_pack([atom], **kwargs)
    second = build_memory_clause_pack([replace(atom)], **kwargs)
    assert first.to_dict() == second.to_dict()
