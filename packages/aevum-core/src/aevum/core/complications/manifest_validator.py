"""
ManifestValidator — validate complication manifests.

Validates:
1. Required fields are present and well-formed (schema check)
2. Ed25519 signature if public_key is provided (optional in Phase 6)

Spec Section 11.4.
"""

from __future__ import annotations

import base64
import json
import logging
from typing import Any

logger = logging.getLogger(__name__)

REQUIRED_FIELDS = [
    "name", "version", "description", "capabilities",
    "classification_max", "functions", "auth", "schema_version",
]


class ManifestValidator:

    def validate(self, manifest: dict[str, Any]) -> list[str]:
        """
        Validate a complication manifest.

        Returns a list of error strings. Empty list = valid.
        Logs a warning (does not fail) if public_key is None.
        """
        errors: list[str] = []

        # Schema: required fields
        for field in REQUIRED_FIELDS:
            if field not in manifest:
                errors.append(f"Missing required field: '{field}'")

        if errors:
            return errors  # Don't go further if fields are missing

        # name: non-empty string
        if not isinstance(manifest["name"], str) or not manifest["name"]:
            errors.append("'name' must be a non-empty string")

        # version: non-empty string (SemVer not enforced here)
        if not isinstance(manifest["version"], str) or not manifest["version"]:
            errors.append("'version' must be a non-empty string")

        # capabilities: non-empty list
        if not isinstance(manifest["capabilities"], list) or not manifest["capabilities"]:
            errors.append("'capabilities' must be a non-empty list")

        # classification_max: 0-3
        cl = manifest.get("classification_max")
        if cl not in (0, 1, 2, 3):
            errors.append("'classification_max' must be 0, 1, 2, or 3")

        # schema_version: "1.0"
        if manifest.get("schema_version") != "1.0":
            errors.append("'schema_version' must be '1.0'")

        # functions: subset of the five
        valid_fns = {"ingest", "query", "review", "commit", "replay"}
        fns = manifest.get("functions", [])
        if not isinstance(fns, list) or not fns:
            errors.append("'functions' must be a non-empty list")
        else:
            invalid = set(fns) - valid_fns
            if invalid:
                errors.append(f"'functions' contains invalid values: {invalid}")

        # Ed25519 signature (optional in Phase 6)
        public_key = manifest.get("auth", {}).get("public_key")
        if public_key is None:
            logger.warning(
                "Complication '%s' has no public_key — signature verification skipped. "
                "Mandatory signing will be enforced when a marketplace exists.",
                manifest.get("name", "unknown"),
            )
        else:
            # Verify signature if both key and signature are present
            sig_errors = self._verify_signature(manifest, public_key)
            errors.extend(sig_errors)

        return errors

    def _verify_signature(
        self, manifest: dict[str, Any], public_key_b64: str
    ) -> list[str]:
        """Verify Ed25519 signature over the manifest content."""
        try:
            from cryptography.exceptions import InvalidSignature
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

            signature_b64 = manifest.get("auth", {}).get("signature")
            if not signature_b64:
                return ["'auth.signature' is required when 'auth.public_key' is present"]

            # Reconstruct signing content (all fields except signature)
            signing_manifest = {
                k: v for k, v in manifest.items()
                if not (k == "auth" and "signature" in manifest.get("auth", {}))
            }
            canonical = json.dumps(signing_manifest, sort_keys=True, separators=(",", ":")).encode()

            pub_key_bytes = base64.urlsafe_b64decode(public_key_b64 + "==")
            pub_key = Ed25519PublicKey.from_public_bytes(pub_key_bytes)
            sig_bytes = base64.urlsafe_b64decode(signature_b64 + "==")
            pub_key.verify(sig_bytes, canonical)
            return []
        except InvalidSignature:
            return ["Ed25519 signature verification failed"]
        except Exception as e:
            return [f"Signature verification error: {e}"]
