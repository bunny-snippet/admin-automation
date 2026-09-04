from __future__ import annotations

import base64
import binascii
import json
import re
from pathlib import Path
from typing import Any

from django.conf import settings
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .release_updates import DESKTOP_RELEASE_PUBLIC_KEY_B64


SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
VERSION_PATTERN = re.compile(r"^[0-9]+(?:\.[0-9]+){2,3}$")
DOWNLOAD_PATH = "/api/v1/optix-migration-installer/"
PRODUCT = "optix-migration"
SCHEMA_VERSION = 1


def canonical_optix_migration_payload(
    *, version: str, build_number: int, size: int, sha256: str
) -> bytes:
    return json.dumps(
        {
            "build_number": int(build_number),
            "product": PRODUCT,
            "schema_version": SCHEMA_VERSION,
            "sha256": str(sha256),
            "size": int(size),
            "version": str(version),
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def optix_migration_manifest() -> dict[str, Any] | None:
    """Return the configured signed installer, or None when rollout is not ready."""

    raw_path = str(settings.OPTIX_MIGRATION_INSTALLER_PATH or "").strip()
    version = str(settings.OPTIX_MIGRATION_INSTALLER_VERSION or "").strip()
    build_number = int(settings.OPTIX_MIGRATION_INSTALLER_BUILD or 0)
    size = int(settings.OPTIX_MIGRATION_INSTALLER_SIZE or 0)
    sha256 = str(settings.OPTIX_MIGRATION_INSTALLER_SHA256 or "").strip().lower()
    signature = str(settings.OPTIX_MIGRATION_INSTALLER_SIGNATURE_B64 or "").strip()
    if not raw_path or not VERSION_PATTERN.fullmatch(version):
        return None
    if build_number < 1 or size < 1 or not SHA256_PATTERN.fullmatch(sha256):
        return None
    try:
        signature_raw = base64.b64decode(signature, validate=True)
        public_raw = base64.b64decode(DESKTOP_RELEASE_PUBLIC_KEY_B64, validate=True)
    except (binascii.Error, ValueError):
        return None
    path = Path(raw_path).expanduser().resolve()
    try:
        if (
            len(signature_raw) != 64
            or len(public_raw) != 32
            or not path.is_file()
            or path.stat().st_size != size
        ):
            return None
    except OSError:
        return None
    try:
        Ed25519PublicKey.from_public_bytes(public_raw).verify(
            signature_raw,
            canonical_optix_migration_payload(
                version=version,
                build_number=build_number,
                size=size,
                sha256=sha256,
            ),
        )
    except (InvalidSignature, ValueError):
        return None
    return {
        "schema_version": SCHEMA_VERSION,
        "product": PRODUCT,
        "version": version,
        "build_number": build_number,
        "size": size,
        "sha256": sha256,
        "signature": signature,
        "download_path": DOWNLOAD_PATH,
    }


def optix_migration_installer_path() -> Path | None:
    manifest = optix_migration_manifest()
    if manifest is None:
        return None
    return Path(settings.OPTIX_MIGRATION_INSTALLER_PATH).expanduser().resolve()
