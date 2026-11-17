"""Text and dict renderers for :class:`AuditReport`."""

from __future__ import annotations

from dataclasses import asdict, is_dataclass
from enum import Enum

from .models import AuditReport, DirectiveOrigin, EffectiveValue

KEY_ORDER = (
    "User",
    "Group",
    "ExecStart",
    "CapabilityBoundingSet",
    "ProtectSystem",
    "ProtectHome",
    "PrivateTmp",
    "ReadWritePaths",
    "ReadOnlyPaths",
    "InaccessiblePaths",
    "NoNewPrivileges",
    "Environment",
    "EnvironmentFiles",
    "WorkingDirectory",
)


def _origin_suffix(origin: DirectiveOrigin | None) -> str:
    if origin is None:
        return "(no directive found)"
    return f"<- {origin.path}:{origin.line} [{origin.section}]"


def _format_value(value: EffectiveValue) -> str:
    if isinstance(value.value, tuple):
        return " ".join(value.value) if value.value else "<reset / empty>"
    return str(value.value)


def render_text(report: AuditReport) -> str:
    loaded = report.unit
    lines: list[str] = []
    lines.append(f"Audit of {loaded.unit_name}")
    if loaded.instance:
        lines.append(f"template instance: {loaded.instance} (template {loaded.template_name})")
    lines.append("application order:")
    if loaded.main_file is not None:
        lines.append(f"  main   {loaded.main_file.path}")
    else:
        lines.append("  main   <not found>")
    for dropin in loaded.dropins:
        lines.append(f"  dropin {dropin.path}")
    if loaded.mask_paths:
        lines.append(f"  MASKED by {loaded.mask_paths[0]}")

    preset = loaded.preset
    if preset is not None and (preset.origin is not None or preset.preset_files):
        if preset.origin is not None:
            lines.append(
                f"preset: {'enable' if preset.enabled else 'disable'} "
                f"({preset.matched_rule}) <- {preset.origin.path}:{preset.origin.line}"
            )
        else:
            lines.append("preset: no matching rule (default policy applies)")

    lines.append("")
    lines.append("effective settings:")
    rendered_keys: set[str] = set()
    for key in KEY_ORDER:
        value = report.config.get(key)
        if value is None:
            continue
        rendered_keys.add(key.lower())
        origin = value.last_origin
        lines.append(f"  {key}={_format_value(value)}  {_origin_suffix(origin)}")
    for value in sorted(
        (item for item in report.config.values.values() if item.key.lower() not in rendered_keys),
        key=lambda item: (item.section, item.key),
    ):
        lines.append(
            f"  [{value.section}] {value.key}={_format_value(value)}  "
            f"{_origin_suffix(value.last_origin)}"
        )

    if report.exec_commands:
        lines.append("")
        lines.append("exec commands:")
        for command in report.exec_commands:
            resolved = command.executable or "<unresolved>"
            lines.append(
                f"  {command.directive} {' '.join(command.argv) or '<empty>'} "
                f"-> {resolved}  {_origin_suffix(command.origin)}"
            )

    if report.environment_files:
        lines.append("")
        lines.append("environment files:")
        for origin in report.environment_files:
            lines.append(f"  {origin.path}  {_origin_suffix(origin)}")

    if report.findings:
        lines.append("")
        lines.append("findings:")
        order = {"high": 0, "medium": 1, "low": 2, "info": 3}
        for finding in sorted(
            report.findings, key=lambda item: (order[item.severity.value], item.code)
        ):
            line = f"  [{finding.severity.value.upper():6}] {finding.code}: {finding.message}"
            lines.append(line)
            if finding.origin is not None:
                lines.append(f"             effective at {_origin_suffix(finding.origin)}")

    if report.warnings:
        lines.append("")
        lines.append("warnings:")
        for warning in report.warnings:
            lines.append(f"  - {warning}")

    return "\n".join(lines)


def _default(obj: object) -> object:
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, frozenset):
        return sorted(obj)
    if is_dataclass(obj):
        return asdict(obj)
    if isinstance(obj, tuple):
        return list(obj)
    raise TypeError(f"not serializable: {type(obj)!r}")


def report_to_dict(report: AuditReport) -> dict:
    return {
        "unit": asdict(report.unit),
        "effective": {
            value.key: {
                "section": value.section,
                "value": list(value.value) if isinstance(value.value, tuple) else value.value,
                "origin": asdict(value.last_origin) if value.last_origin else None,
                "all_origins": [asdict(origin) for origin in value.origins],
            }
            for value in report.config.values.values()
        },
        "exec_commands": [asdict(command) for command in report.exec_commands],
        "environment": report.environment,
        "findings": [asdict(finding) for finding in report.findings],
        "warnings": list(report.warnings),
    }
