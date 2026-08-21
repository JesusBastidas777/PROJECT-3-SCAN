"""Typed scan request and canonical effective-configuration helpers."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from typing import Any

from scanner.contract import semantic_hash


@dataclass(frozen=True)
class ScanRequest:
    target: str
    schema_version: str
    profile: str | None
    profile_version: str | None

    @classmethod
    def from_namespace(cls, args: argparse.Namespace) -> "ScanRequest":
        return cls(str(args.target), str(args.schema_version), getattr(args, "profile", None), getattr(args, "profile_version", None))


@dataclass(frozen=True)
class EffectiveConfiguration:
    value: dict[str, Any]

    @property
    def fingerprint(self) -> str:
        return semantic_hash(self.value)


def effective_configuration(value: dict[str, Any]) -> EffectiveConfiguration:
    """Canonicalize a fully expanded configuration without changing semantics."""
    normalized = dict(value)
    normalized["ports"] = sorted(set(normalized.get("ports", [])))
    return EffectiveConfiguration(normalized)
