from __future__ import annotations

import hashlib

import pytest

from defense_arena.armor_first_move_cassette import (
    FrozenFirstMoveCassette,
    FrozenFirstMoveCassetteBundle,
    FrozenFirstMoveCassetteError,
    cassette_from_prefreeze_row,
)


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _cassette() -> FrozenFirstMoveCassette:
    request = "fixture first request"
    return FrozenFirstMoveCassette(
        behavior_id="behavior-one",
        request_text=request,
        request_sha256=_sha(request),
        action_sha256=_sha("fixture query action"),
        image_assets=(("image-001", _sha("pixels-one")),),
    )


def test_private_cassette_round_trip_is_explicitly_raw_and_response_free():
    cassette = _cassette()
    serialized = cassette.to_dict()

    assert serialized["raw_attack_or_response_text_included"] is True
    assert serialized["target_response_included"] is False
    assert FrozenFirstMoveCassette.from_mapping(serialized) == cassette


def test_private_cassette_attests_ordered_assets():
    cassette = FrozenFirstMoveCassette(
        behavior_id="behavior-one",
        request_text="fixture",
        request_sha256=_sha("fixture"),
        action_sha256=_sha("action"),
        image_assets=(
            ("image-001", _sha("pixels-one")),
            ("image-002", _sha("pixels-two")),
        ),
    )

    with pytest.raises(FrozenFirstMoveCassetteError, match="image_assets"):
        cassette.attest_contract(
            behavior_id="behavior-one",
            request_sha256=_sha("fixture"),
            action_sha256=_sha("action"),
            asset_hashes={
                "image-002": _sha("pixels-two"),
                "image-001": _sha("pixels-one"),
            },
        )


def test_private_cassette_rejects_request_tamper():
    serialized = _cassette().to_dict()
    serialized["request_text"] = "tampered"

    with pytest.raises(FrozenFirstMoveCassetteError, match="request text hash"):
        FrozenFirstMoveCassette.from_mapping(serialized)


def test_private_v2_bundle_round_trip_contains_v1_equivalent_cassettes():
    first = _cassette()
    second_request = "second fixture first request"
    second = FrozenFirstMoveCassette(
        behavior_id="behavior-two",
        request_text=second_request,
        request_sha256=_sha(second_request),
        action_sha256=_sha("second fixture query action"),
        image_assets=(("image-002", _sha("pixels-two")),),
    )
    bundle = FrozenFirstMoveCassetteBundle((first, second))

    serialized = bundle.to_dict()

    assert serialized["schema_version"] == 2
    assert serialized["artifact_type"] == (
        "armor-stage0-frozen-first-move-bundle-v2"
    )
    assert serialized["raw_attack_or_response_text_included"] is True
    assert serialized["target_response_included"] is False
    assert serialized["cassettes"] == [first.to_dict(), second.to_dict()]
    assert FrozenFirstMoveCassetteBundle.from_mapping(serialized) == bundle
    assert bundle.by_behavior_id() == {
        "behavior-one": first,
        "behavior-two": second,
    }


def test_private_v2_bundle_rejects_duplicate_behavior_ids():
    cassette = _cassette()

    with pytest.raises(
        FrozenFirstMoveCassetteError,
        match="duplicate cassette behavior_id",
    ):
        FrozenFirstMoveCassetteBundle((cassette, cassette))

    serialized = FrozenFirstMoveCassetteBundle((cassette,)).to_dict()
    serialized["cassettes"].append(cassette.to_dict())
    with pytest.raises(
        FrozenFirstMoveCassetteError,
        match="duplicate cassette behavior_id",
    ):
        FrozenFirstMoveCassetteBundle.from_mapping(serialized)


def test_private_v2_bundle_rejects_target_response_marker_or_nested_raw_fields():
    serialized = FrozenFirstMoveCassetteBundle((_cassette(),)).to_dict()
    serialized["target_response_included"] = True
    with pytest.raises(FrozenFirstMoveCassetteError, match="target response"):
        FrozenFirstMoveCassetteBundle.from_mapping(serialized)

    serialized = FrozenFirstMoveCassetteBundle((_cassette(),)).to_dict()
    serialized["cassettes"][0]["target_response"] = "must never be stored"
    with pytest.raises(FrozenFirstMoveCassetteError, match="invalid"):
        FrozenFirstMoveCassetteBundle.from_mapping(serialized)


def test_cassette_extracts_only_prefrozen_request_and_ordered_image_contract():
    request = "fixture first request"
    request_hash = _sha(request)
    action_hash = _sha("fixture action")
    image_hash = _sha("fixture pixels")
    row = {
        "history": [
            {
                "turns": [{"text": request, "images": ["img_1"]}],
                "request_sha256": request_hash,
                "action_sha256": action_hash,
                "image_content_sha256": [image_hash],
                "response": "must not enter cassette",
            }
        ]
    }

    cassette = cassette_from_prefreeze_row(
        row,
        behavior_id="behavior-one",
        request_sha256=request_hash,
        action_sha256=action_hash,
        image_assets=(("image-001", image_hash),),
    )

    assert cassette.request_text == request
    assert "must not enter cassette" not in str(cassette.to_dict())
