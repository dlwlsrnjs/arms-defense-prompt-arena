"""Private cassettes for prefrozen first target requests.

The public Stage-0 pair wrapper intentionally contains hashes only.  A live
paired run nevertheless needs the exact first request and ordered image bytes
so that every defense arm receives the same opening move.  This module keeps
that raw request in a separate, explicitly marked artifact and validates every
field against the hashes already attested by the public contract.

Only first moves are stored.  Target responses are never written here; after a
first response the attacker resumes its normal adaptive loop. Schema v1 remains
the single-behavior artifact. Schema v2 is a strict bundle of those v1-equivalent
cassettes keyed semantically by their unique ``behavior_id`` values.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any


class FrozenFirstMoveCassetteError(ValueError):
    """Raised when a private first-move cassette fails attestation."""


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _is_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and value == value.lower()
        and all(character in "0123456789abcdef" for character in value)
    )


def _require_sha256(value: Any, label: str) -> str:
    if not _is_sha256(value):
        raise FrozenFirstMoveCassetteError(
            f"{label} must be a lowercase SHA-256 digest"
        )
    return str(value)


@dataclass(frozen=True)
class FrozenFirstMoveCassette:
    """Exact opening request plus ordered, contract-named image hashes."""

    behavior_id: str
    request_text: str
    request_sha256: str
    action_sha256: str
    image_assets: tuple[tuple[str, str], ...]

    def __post_init__(self) -> None:
        if not isinstance(self.behavior_id, str) or not self.behavior_id.strip():
            raise FrozenFirstMoveCassetteError("behavior_id cannot be empty")
        if not isinstance(self.request_text, str):
            raise FrozenFirstMoveCassetteError("request_text must be a string")
        request_hash = _require_sha256(self.request_sha256, "request_sha256")
        _require_sha256(self.action_sha256, "action_sha256")
        if _sha256_text(self.request_text) != request_hash:
            raise FrozenFirstMoveCassetteError("request text hash mismatch")
        if not self.image_assets:
            raise FrozenFirstMoveCassetteError(
                "a frozen first move must contain at least one image"
            )
        names: set[str] = set()
        for index, item in enumerate(self.image_assets, start=1):
            if not isinstance(item, tuple) or len(item) != 2:
                raise FrozenFirstMoveCassetteError(
                    f"image_assets[{index}] must be a name/hash pair"
                )
            name, digest = item
            if not isinstance(name, str) or not name.strip() or name in names:
                raise FrozenFirstMoveCassetteError(
                    f"image_assets[{index}] has an empty or duplicate name"
                )
            names.add(name)
            _require_sha256(digest, f"image_assets[{index}].content_sha256")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "artifact_type": "armor-stage0-frozen-first-move-v1",
            "behavior_id": self.behavior_id,
            "request_text": self.request_text,
            "request_sha256": self.request_sha256,
            "action_sha256": self.action_sha256,
            "images": [
                {"asset_id": name, "content_sha256": digest}
                for name, digest in self.image_assets
            ],
            "raw_attack_or_response_text_included": True,
            "target_response_included": False,
        }

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> FrozenFirstMoveCassette:
        if not isinstance(value, Mapping):
            raise FrozenFirstMoveCassetteError("cassette must be an object")
        expected_keys = {
            "schema_version",
            "artifact_type",
            "behavior_id",
            "request_text",
            "request_sha256",
            "action_sha256",
            "images",
            "raw_attack_or_response_text_included",
            "target_response_included",
        }
        if set(value) != expected_keys:
            raise FrozenFirstMoveCassetteError(
                "cassette fields do not match the frozen-first-move schema"
            )
        if value.get("schema_version") != 1:
            raise FrozenFirstMoveCassetteError("cassette schema_version must be 1")
        if value.get("artifact_type") != "armor-stage0-frozen-first-move-v1":
            raise FrozenFirstMoveCassetteError("invalid cassette artifact_type")
        if value.get("raw_attack_or_response_text_included") is not True:
            raise FrozenFirstMoveCassetteError(
                "cassette must explicitly mark raw attack text"
            )
        if value.get("target_response_included") is not False:
            raise FrozenFirstMoveCassetteError(
                "cassette must not contain a target response"
            )
        images = value.get("images")
        if not isinstance(images, Sequence) or isinstance(images, (str, bytes)):
            raise FrozenFirstMoveCassetteError("cassette images must be a list")
        image_assets: list[tuple[str, str]] = []
        for index, row in enumerate(images, start=1):
            if not isinstance(row, Mapping) or set(row) != {
                "asset_id",
                "content_sha256",
            }:
                raise FrozenFirstMoveCassetteError(
                    f"cassette images[{index}] has invalid fields"
                )
            image_assets.append(
                (
                    str(row.get("asset_id", "")),
                    _require_sha256(
                        row.get("content_sha256"),
                        f"images[{index}].content_sha256",
                    ),
                )
            )
        return cls(
            behavior_id=str(value.get("behavior_id", "")),
            request_text=value.get("request_text"),
            request_sha256=_require_sha256(
                value.get("request_sha256"), "request_sha256"
            ),
            action_sha256=_require_sha256(
                value.get("action_sha256"), "action_sha256"
            ),
            image_assets=tuple(image_assets),
        )

    def attest_contract(
        self,
        *,
        behavior_id: str,
        request_sha256: str,
        action_sha256: str,
        asset_hashes: Mapping[str, str],
    ) -> None:
        """Fail closed unless all raw cassette fields match the public contract."""

        expected_assets = tuple(
            (str(name), str(digest)) for name, digest in asset_hashes.items()
        )
        reasons: list[str] = []
        if self.behavior_id != behavior_id:
            reasons.append("behavior_id")
        if self.request_sha256 != request_sha256:
            reasons.append("request_sha256")
        if self.action_sha256 != action_sha256:
            reasons.append("action_sha256")
        if self.image_assets != expected_assets:
            reasons.append("image_assets")
        if reasons:
            raise FrozenFirstMoveCassetteError(
                "cassette contract mismatch: " + ",".join(reasons)
            )


@dataclass(frozen=True)
class FrozenFirstMoveCassetteBundle:
    """Private schema-v2 collection with one cassette per behavior id."""

    cassettes: tuple[FrozenFirstMoveCassette, ...]

    def __post_init__(self) -> None:
        if not self.cassettes:
            raise FrozenFirstMoveCassetteError(
                "cassette bundle must contain at least one cassette"
            )
        behavior_ids: set[str] = set()
        for index, cassette in enumerate(self.cassettes, start=1):
            if not isinstance(cassette, FrozenFirstMoveCassette):
                raise FrozenFirstMoveCassetteError(
                    f"cassettes[{index}] must be a frozen first-move cassette"
                )
            if cassette.behavior_id in behavior_ids:
                raise FrozenFirstMoveCassetteError(
                    f"duplicate cassette behavior_id: {cassette.behavior_id}"
                )
            behavior_ids.add(cassette.behavior_id)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 2,
            "artifact_type": "armor-stage0-frozen-first-move-bundle-v2",
            "cassettes": [cassette.to_dict() for cassette in self.cassettes],
            "raw_attack_or_response_text_included": True,
            "target_response_included": False,
        }

    @classmethod
    def from_mapping(
        cls,
        value: Mapping[str, Any],
    ) -> FrozenFirstMoveCassetteBundle:
        if not isinstance(value, Mapping):
            raise FrozenFirstMoveCassetteError("cassette bundle must be an object")
        expected_keys = {
            "schema_version",
            "artifact_type",
            "cassettes",
            "raw_attack_or_response_text_included",
            "target_response_included",
        }
        if set(value) != expected_keys:
            raise FrozenFirstMoveCassetteError(
                "cassette bundle fields do not match the schema-v2 bundle"
            )
        if value.get("schema_version") != 2:
            raise FrozenFirstMoveCassetteError(
                "cassette bundle schema_version must be 2"
            )
        if (
            value.get("artifact_type")
            != "armor-stage0-frozen-first-move-bundle-v2"
        ):
            raise FrozenFirstMoveCassetteError(
                "invalid cassette bundle artifact_type"
            )
        if value.get("raw_attack_or_response_text_included") is not True:
            raise FrozenFirstMoveCassetteError(
                "cassette bundle must explicitly mark raw attack text"
            )
        if value.get("target_response_included") is not False:
            raise FrozenFirstMoveCassetteError(
                "cassette bundle must not contain a target response"
            )
        rows = value.get("cassettes")
        if not isinstance(rows, Sequence) or isinstance(rows, (str, bytes)):
            raise FrozenFirstMoveCassetteError(
                "cassette bundle cassettes must be a list"
            )
        cassettes: list[FrozenFirstMoveCassette] = []
        for index, row in enumerate(rows, start=1):
            if not isinstance(row, Mapping):
                raise FrozenFirstMoveCassetteError(
                    f"cassettes[{index}] must be an object"
                )
            try:
                cassettes.append(FrozenFirstMoveCassette.from_mapping(row))
            except FrozenFirstMoveCassetteError as exc:
                raise FrozenFirstMoveCassetteError(
                    f"cassettes[{index}] is invalid: {exc}"
                ) from exc
        return cls(cassettes=tuple(cassettes))

    def by_behavior_id(self) -> dict[str, FrozenFirstMoveCassette]:
        """Return the validated unique behavior routing table."""

        return {cassette.behavior_id: cassette for cassette in self.cassettes}


def cassette_from_prefreeze_row(
    row: Mapping[str, Any],
    *,
    behavior_id: str,
    request_sha256: str,
    action_sha256: str,
    image_assets: Sequence[tuple[str, str]],
) -> FrozenFirstMoveCassette:
    """Extract the private replay payload from an already validated capture row."""

    history = row.get("history") if isinstance(row, Mapping) else None
    record = history[0] if isinstance(history, list) and history else None
    turns = record.get("turns") if isinstance(record, Mapping) else None
    turn = turns[0] if isinstance(turns, list) and len(turns) == 1 else None
    if not isinstance(turn, Mapping):
        raise FrozenFirstMoveCassetteError(
            "prefreeze row must contain exactly one resolved first turn"
        )
    text = turn.get("text")
    image_ids = turn.get("images")
    observed_image_hashes = record.get("image_content_sha256")
    if not isinstance(text, str):
        raise FrozenFirstMoveCassetteError("prefreeze first-turn text is missing")
    if not isinstance(image_ids, list) or not all(
        isinstance(value, str) for value in image_ids
    ):
        raise FrozenFirstMoveCassetteError("prefreeze first-turn image ids are invalid")
    if not isinstance(observed_image_hashes, list):
        raise FrozenFirstMoveCassetteError("prefreeze image hashes are missing")
    expected_assets = tuple((str(name), str(digest)) for name, digest in image_assets)
    if len(image_ids) != len(expected_assets):
        raise FrozenFirstMoveCassetteError("prefreeze image count mismatch")
    if tuple(observed_image_hashes) != tuple(digest for _, digest in expected_assets):
        raise FrozenFirstMoveCassetteError("prefreeze ordered image hash mismatch")
    if _sha256_text(text) != request_sha256 or record.get("request_sha256") != request_sha256:
        raise FrozenFirstMoveCassetteError("prefreeze request hash mismatch")
    if record.get("action_sha256") != action_sha256:
        raise FrozenFirstMoveCassetteError("prefreeze action hash mismatch")
    cassette = FrozenFirstMoveCassette(
        behavior_id=behavior_id,
        request_text=text,
        request_sha256=request_sha256,
        action_sha256=action_sha256,
        image_assets=expected_assets,
    )
    cassette.attest_contract(
        behavior_id=behavior_id,
        request_sha256=request_sha256,
        action_sha256=action_sha256,
        asset_hashes=dict(expected_assets),
    )
    return cassette
