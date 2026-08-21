"""Typed scan request and canonical effective-configuration helpers."""

from __future__ import annotations

import argparse
from dataclasses import dataclass, fields
from pathlib import Path
from typing import Any

from scanner.contract import semantic_hash


@dataclass(frozen=True)
class ScanRequest:
    target: str
    schema_version: str
    profile: str | None
    profile_version: str | None
    options: tuple[tuple[str, Any], ...] = ()

    @classmethod
    def from_namespace(cls, args: argparse.Namespace) -> "ScanRequest":
        excluded={"target","schema_version","profile","profile_version"}
        options=tuple(sorted((key,value) for key,value in vars(args).items() if key not in excluded))
        return cls(str(args.target), str(args.schema_version), getattr(args, "profile", None), getattr(args, "profile_version", None), options)

    def option(self, name: str, default: Any = None) -> Any:
        return dict(self.options).get(name, default)

@dataclass(frozen=True)
class MeasurementConfiguration:
    ports: tuple[int, ...]; discovery: str; capabilities: tuple[str, ...]

@dataclass(frozen=True)
class ExecutionLimits:
    workers: int; max_hosts: int; ping_timeout: float; connect_timeout: float

@dataclass(frozen=True)
class TargetSelectionPolicy:
    include_hosts: tuple[str, ...]=(); exclude_hosts: tuple[str, ...]=(); include_cidrs: tuple[str, ...]=(); exclude_cidrs: tuple[str, ...]=()

@dataclass(frozen=True)
class OutputConfiguration:
    output: str; history_dir: Path|None; events_output: Path|None

@dataclass(frozen=True)
class PrivacyConfiguration:
    events: str; neighbors: str

@dataclass(frozen=True)
class ResumePolicy:
    checkpoint_dir: Path|None=None; resume: str|None=None

@dataclass(frozen=True)
class ResolvedScanConfiguration:
    request: ScanRequest
    measurement: MeasurementConfiguration
    execution: ExecutionLimits
    target_selection: TargetSelectionPolicy
    output: OutputConfiguration
    privacy: PrivacyConfiguration
    resume: ResumePolicy
    values: tuple[tuple[str, Any], ...]

    def namespace(self) -> argparse.Namespace:
        values=dict(self.values); values.update(target=self.request.target,schema_version=self.request.schema_version,profile=self.request.profile,profile_version=self.request.profile_version)
        return argparse.Namespace(**values)

def resolve_request(request: ScanRequest) -> ResolvedScanConfiguration:
    values=dict(request.options)
    enabled=tuple(name for name,flag in (("banners",values.get("collect_banners")),("tls",values.get("collect_tls")),("dns",values.get("resolve_names")),("neighbors",values.get("collect_neighbors")),("http",values.get("collect_http"))) if flag)
    return ResolvedScanConfiguration(request,MeasurementConfiguration(tuple(values.get("ports",())),str(values.get("discovery","icmp")),enabled),ExecutionLimits(int(values.get("workers",64)),int(values.get("max_hosts",4096)),float(values.get("ping_timeout",1.0)),float(values.get("connect_timeout",1.0))),TargetSelectionPolicy(),OutputConfiguration(str(values.get("output","-")),values.get("history_dir"),values.get("events_output")),PrivacyConfiguration(str(values.get("events_privacy","full")),str(values.get("neighbor_privacy","hash-only"))),ResumePolicy(),tuple(sorted(values.items())))


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
