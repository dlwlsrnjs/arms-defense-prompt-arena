"""Canonical hashes for Stage-0 multimodal assets.

ARMS records image provenance from the decoded image (mode, dimensions, and
pixels), not from a container such as PNG or WebP. Stage-0 must therefore use
the same content hash when it validates an asset path. Non-image fixtures are
kept backward compatible by falling back to their raw byte hash.
"""

from __future__ import annotations

import hashlib
import io
from pathlib import Path
from typing import Any

from PIL import Image, UnidentifiedImageError


def image_content_sha256(image: Any) -> str:
    """Hash an already-decoded image exactly as ARMS instrumentation does."""

    digest = hashlib.sha256()
    digest.update(str(getattr(image, "mode", "")).encode("ascii", errors="replace"))
    digest.update(repr(getattr(image, "size", None)).encode("ascii", errors="replace"))
    digest.update(image.tobytes())
    return digest.hexdigest()


def _raw_sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def asset_bytes_sha256(value: bytes) -> str:
    """Return decoded-image content SHA, or raw SHA for a non-image payload."""

    try:
        with Image.open(io.BytesIO(value)) as image:
            image.load()
            return image_content_sha256(image)
    except (OSError, UnidentifiedImageError):
        return _raw_sha256(value)


def asset_file_sha256(path: str | Path) -> str:
    """Return the canonical Stage-0 content hash for one local asset file."""

    source = Path(path)
    try:
        with Image.open(source) as image:
            image.load()
            return image_content_sha256(image)
    except (OSError, UnidentifiedImageError):
        digest = hashlib.sha256()
        with source.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
