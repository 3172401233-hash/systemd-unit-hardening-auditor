"""Data structures shared by the parser, loader and auditor."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


@dataclass(frozen=True)
class DirectiveOrigin:
    """Where a directive (or one entry of a list directive) came from."""

    path: str
    section: str
    line: int
    key: str
    raw_value: str
    kind: str = "unit"  # "main" | "dropin" | "preset" | "envfile"


@dataclass(frozen=True)
class ParsedLine:
    """One ``Key=Value`` occurrence inside a parsed file."""

    section: str
    key: str
    value: str
    line: int


@dataclass(frozen=True)
class ParsedFile:
    """A unit file, drop-in file or environment file after parsing."""

    path: str
    kind: str  # "main" | "dropin" | "preset" | "envfile"
    lines: tuple[ParsedLine, ...] = ()
    parse_errors: tuple[str, ...] = ()

    def directives(self, section: str, key: str) -> tuple[ParsedLine, ...]:
        key_l = key.lower()
        return tuple(
            item
            for item in self.lines
            if item.section.lower() == section.lower() and item.key.lower() == key_l
        )


@dataclass(frozen=True)
class EffectiveValue:
    """A directive value after merge, with the origin that made it effective."""

    key: str
    section: str
    value: object
    origins: tuple[DirectiveOrigin, ...]

    @property
    def last_origin(self) -> Optional[DirectiveOrigin]:
        return self.origins[-1] if self.origins else None


@dataclass(frozen=True)
class ExecCommand:
    """One ExecStart/ExecStartPre/... command after prefix/env expansion."""

    directive: str
    argv: tuple[str, ...]
    executable: Optional[str]
    prefixes: str
    ignore_failure: bool
    origin: DirectiveOrigin


class FindingSeverity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass(frozen=True)
class Finding:
    """A single hardening / file-system exposure observation."""

    code: str
    severity: FindingSeverity
    message: str
    target_path: Optional[str] = None
    component: Optional[str] = None
    principal: Optional[str] = None
    mode: Optional[int] = None
    origin: Optional[DirectiveOrigin] = None


@dataclass(frozen=True)
class PresetDecision:
    """Result of evaluating systemd preset files for a unit."""

    enabled: Optional[bool]
    origin: Optional[DirectiveOrigin]
    matched_rule: Optional[str]
    preset_files: tuple[str, ...] = ()


@dataclass
class LoadedUnit:
    """Everything that was read from disk for one unit (or instance)."""

    unit_name: str
    template_name: Optional[str]
    instance: Optional[str]
    main_file: Optional[ParsedFile]
    main_candidates: tuple[str, ...]
    dropin_dirs: tuple[str, ...]
    dropins: tuple[ParsedFile, ...]
    preset: Optional[PresetDecision]
    search_roots: tuple[str, ...]
    mask_paths: tuple[str, ...] = ()

    @property
    def all_files(self) -> tuple[ParsedFile, ...]:
        files: list[ParsedFile] = []
        if self.main_file is not None:
            files.append(self.main_file)
        files.extend(self.dropins)
        return tuple(files)


@dataclass
class EffectiveConfig:
    """Merged directive map plus convenience accessors for hardening keys."""

    values: dict[tuple[str, str], EffectiveValue] = field(default_factory=dict)

    def get(self, key: str, section: str = "Service") -> Optional[EffectiveValue]:
        return self.values.get((section.lower(), key.lower()))

    def scalar(self, key: str, section: str = "Service") -> Optional[str]:
        item = self.get(key, section)
        return None if item is None else str(item.value)

    def entries(self, key: str, section: str = "Service") -> list[tuple[str, DirectiveOrigin]]:
        item = self.get(key, section)
        if item is None:
            return []
        return list(zip(item.value, item.origins))


@dataclass
class AuditReport:
    """Final output: effective config, commands and findings."""

    unit: LoadedUnit
    config: EffectiveConfig
    exec_commands: tuple[ExecCommand, ...]
    environment: dict[str, str]
    environment_files: tuple[DirectiveOrigin, ...]
    findings: tuple[Finding, ...]
    warnings: tuple[str, ...]

    def findings_by_severity(self) -> dict[str, list[Finding]]:
        grouped: dict[str, list[Finding]] = {}
        for finding in self.findings:
            grouped.setdefault(finding.severity.value, []).append(finding)
        return grouped

    def to_text(self) -> str:
        from .report import render_text

        return render_text(self)

    def to_dict(self) -> dict:
        from .report import report_to_dict

        return report_to_dict(self)
