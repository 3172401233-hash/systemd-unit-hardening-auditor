"""High-level audit: effective hardening values + replaceable-path findings."""

from __future__ import annotations

import os
import shlex

from .expansion import expand_env, expand_specifiers, parse_exec_command
from .loader import LoadedUnit, load_unit
from .merge import merge_files
from .models import (
    AuditReport,
    DirectiveOrigin,
    EffectiveConfig,
    ExecCommand,
    Finding,
    FindingSeverity,
)
from .parser import parse_env_file
from .paths import analyze_path, describe_mode

EXEC_DIRECTIVES = (
    "ExecStart",
    "ExecStartPre",
    "ExecStartPost",
    "ExecReload",
    "ExecStop",
    "ExecStopPost",
)

def audit_unit(
    unit_name: str,
    search_roots: list[str] | tuple[str, ...] | None = None,
    path_prefix: str = "",
    owner_override: dict[str, tuple[int, int]] | None = None,
) -> AuditReport:
    """Audit one unit name (template instances allowed) against files on disk.

    ``path_prefix`` is prepended to every analyzed filesystem path, which lets
    tests point at a staged copy of ``/etc``/``/usr``.
    """
    loaded = load_unit(unit_name, search_roots)
    return audit_loaded(loaded, path_prefix=path_prefix, owner_override=owner_override)


def audit_loaded(
    loaded: LoadedUnit,
    path_prefix: str = "",
    owner_override: dict[str, tuple[int, int]] | None = None,
) -> AuditReport:
    warnings = _collect_parse_warnings(loaded)
    if loaded.main_file is None and not loaded.dropins and not loaded.mask_paths:
        warnings.append(
            f"no unit file or drop-in found for {loaded.unit_name} in "
            f"{', '.join(loaded.search_roots)}"
        )
    if loaded.mask_paths:
        warnings.append(f"unit is masked by symlink to /dev/null: {loaded.mask_paths[0]}")

    config = merge_files(
        list(loaded.all_files),
        unit_name=loaded.unit_name,
        instance=loaded.instance,
    )
    environment, env_origins, env_warnings = _load_environment(loaded, config, path_prefix)
    warnings.extend(env_warnings)

    exec_commands = _parse_exec_commands(loaded, config, environment)
    findings = list(_hardening_findings(config))
    effective_override = _build_owner_override(path_prefix)
    if owner_override:
        effective_override.update(owner_override)
    findings.extend(
        _path_findings(
            config,
            exec_commands,
            env_origins,
            environment,
            loaded,
            path_prefix,
            effective_override,
        )
    )
    findings = _dedupe_findings(findings)

    return AuditReport(
        unit=loaded,
        config=config,
        exec_commands=tuple(exec_commands),
        environment=environment,
        environment_files=env_origins,
        findings=tuple(findings),
        warnings=tuple(warnings),
    )


def _collect_parse_warnings(loaded: LoadedUnit) -> list[str]:
    warnings: list[str] = []
    for file in loaded.all_files:
        warnings.extend(file.parse_errors)
    return warnings


def _load_environment(
    loaded: LoadedUnit,
    config: EffectiveConfig,
    path_prefix: str,
) -> tuple[dict[str, str], tuple[DirectiveOrigin, ...], list[str]]:
    environment: dict[str, str] = {}
    file_origins: list[DirectiveOrigin] = []
    warnings: list[str] = []

    # Inline Environment= assignments first, then EnvironmentFile= in order.
    for token, origin in config.entries("Environment"):
        try:
            pieces = shlex.split(token, comments=True)
        except ValueError as exc:
            warnings.append(f"{origin.path}:{origin.line}: bad Environment quoting: {exc}")
            continue
        for piece in pieces:
            if "=" in piece:
                key, value = piece.split("=", 1)
                environment[key] = value
        # Specifiers such as %i inside inline assignments are expanded now;
        # later lines may reference the resulting variables via $NAME.
        environment = {
            key: expand_specifiers(value, loaded.unit_name, loaded.instance)
            for key, value in environment.items()
        }

    for token, origin in config.entries("EnvironmentFile"):
        optional = token.startswith("-")
        raw_path = token[1:] if optional else token
        expanded = expand_specifiers(raw_path, loaded.unit_name, loaded.instance)
        full_path = _prefixed(expanded, path_prefix)
        file_origin = DirectiveOrigin(
            path=full_path,
            section="Service",
            line=origin.line,
            key="EnvironmentFile",
            raw_value=expanded,
            kind="envfile",
        )
        if not os.path.exists(full_path):
            if not optional:
                warnings.append(
                    f"EnvironmentFile {expanded} referenced at {origin.path}:{origin.line} is missing"
                )
            continue
        values, parse_warnings = parse_env_file(full_path)
        warnings.extend(parse_warnings)
        environment.update(values)
        file_origins.append(file_origin)

    return environment, tuple(file_origins), warnings


def _parse_exec_commands(
    loaded: LoadedUnit,
    config: EffectiveConfig,
    environment: dict[str, str],
) -> list[ExecCommand]:
    commands: list[ExecCommand] = []
    path_value = environment.get("PATH")
    for directive in EXEC_DIRECTIVES:
        for token, origin in config.entries(directive):
            commands.append(
                parse_exec_command(
                    directive=directive,
                    raw_value=token,
                    origin=origin,
                    environment=environment,
                    unit_name=loaded.unit_name,
                    instance=loaded.instance,
                    path_value=path_value,
                )
            )
    return commands


def _hardening_findings(config: EffectiveConfig) -> list[Finding]:
    findings: list[Finding] = []
    protect_system = config.scalar("ProtectSystem")
    if protect_system is not None and protect_system == "off":
        origin = config.get("ProtectSystem")
        findings.append(
            Finding(
                code="HARDENING_PROTECT_SYSTEM_OFF",
                severity=FindingSeverity.HIGH,
                message="ProtectSystem is explicitly disabled; the OS tree is not mounted read-only",
                origin=origin.last_origin if origin else None,
            )
        )
    elif protect_system is None:
        findings.append(
            Finding(
                code="HARDENING_PROTECT_SYSTEM_UNSET",
                severity=FindingSeverity.MEDIUM,
                message="ProtectSystem is not set (defaults to off)",
            )
        )

    protect_home = config.scalar("ProtectHome")
    if protect_home is None:
        findings.append(
            Finding(
                code="HARDENING_PROTECT_HOME_UNSET",
                severity=FindingSeverity.LOW,
                message="ProtectHome is not set; /home, /root and /run/user remain accessible",
            )
        )

    private_tmp = config.scalar("PrivateTmp")
    if private_tmp == "no":
        origin = config.get("PrivateTmp")
        findings.append(
            Finding(
                code="HARDENING_PRIVATE_TMP_OFF",
                severity=FindingSeverity.MEDIUM,
                message="PrivateTmp is explicitly disabled; the service shares /tmp with other processes",
                origin=origin.last_origin if origin else None,
            )
        )

    for key in ("NoNewPrivileges", "LockPersonality", "MemoryDenyWriteExecute", "RestrictSUIDSGID"):
        value = config.scalar(key)
        if value is not None and value.strip().lower() in ("0", "no", "false", "off"):
            origin = config.get(key)
            findings.append(
                Finding(
                    code=f"HARDENING_{key.upper()}_OFF",
                    severity=FindingSeverity.LOW,
                    message=f"{key} is explicitly disabled",
                    origin=origin.last_origin if origin else None,
                )
            )

    cap_value = config.get("CapabilityBoundingSet")
    if cap_value is not None:
        caps = set(cap_value.value)
        dangerous = {"CAP_SYS_ADMIN", "CAP_NET_ADMIN", "CAP_SYS_PTRACE", "CAP_SYS_MODULE",
                     "CAP_DAC_OVERRIDE", "CAP_SETUID", "CAP_SETGID"}
        exposed = sorted(caps & dangerous)
        if exposed:
            findings.append(
                Finding(
                    code="CAPABILITY_DANGEROUS_PRESENT",
                    severity=FindingSeverity.MEDIUM,
                    message="bounding set retains dangerous capabilities: " + ", ".join(exposed),
                    origin=cap_value.last_origin,
                )
            )
        if not caps:
            findings.append(
                Finding(
                    code="CAPABILITY_EMPTY_SET",
                    severity=FindingSeverity.INFO,
                    message="CapabilityBoundingSet was reset to the empty capability set",
                    origin=cap_value.last_origin,
                )
            )
    else:
        findings.append(
            Finding(
                code="CAPABILITY_UNBOUNDED",
                severity=FindingSeverity.MEDIUM,
                message="CapabilityBoundingSet is not set; no capability limits are enforced",
            )
        )
    return findings


def _path_findings(
    config: EffectiveConfig,
    commands: list[ExecCommand],
    env_origins: tuple[DirectiveOrigin, ...],
    environment: dict[str, str],
    loaded: LoadedUnit,
    path_prefix: str,
    owner_override: dict[str, tuple[int, int]],
) -> list[Finding]:
    findings: list[Finding] = []

    # ExecStart/Pre/... executables: replacement means code execution.
    for command in commands:
        if not command.executable:
            continue
        executable = _prefixed(command.executable, path_prefix)
        writers, exists = analyze_path(
            executable, root_prefix=path_prefix, owner_override=owner_override
        )
        if not exists:
            findings.append(
                Finding(
                    code="EXEC_PATH_MISSING",
                    severity=FindingSeverity.LOW,
                    message=f"{command.directive} executable does not exist on disk: {command.executable}",
                    target_path=command.executable,
                    origin=command.origin,
                )
            )
            continue
        for writer in writers:
            findings.append(
                Finding(
                    code="EXEC_PATH_WRITABLE",
                    severity=FindingSeverity.HIGH,
                    message=(
                        f"{command.directive} target {command.executable} is reachable through a "
                        f"{writer.principal}-writable component ({describe_mode(writer.mode)})"
                    ),
                    target_path=command.executable,
                    component=writer.component,
                    principal=writer.principal,
                    mode=writer.mode,
                    origin=command.origin,
                )
            )

    # Environment files: replacement injects variables into the service.
    for env_origin in env_origins:
        writers, exists = analyze_path(
            env_origin.path, root_prefix=path_prefix, owner_override=owner_override
        )
        if not exists:
            continue
        for writer in writers:
            findings.append(
                Finding(
                    code="ENVFILE_WRITABLE",
                    severity=FindingSeverity.MEDIUM,
                    message=(
                        f"environment file {env_origin.raw_value} is reachable through a "
                        f"{writer.principal}-writable component ({describe_mode(writer.mode)})"
                    ),
                    target_path=env_origin.raw_value,
                    component=writer.component,
                    principal=writer.principal,
                    mode=writer.mode,
                    origin=env_origin,
                )
            )

    # ReadWritePaths carves writable holes out of ProtectSystem/ProtectHome.
    for path, origin in config.entries("ReadWritePaths"):
        expanded = expand_env(
            expand_specifiers(path, loaded.unit_name, loaded.instance), environment
        )
        full = _prefixed(expanded, path_prefix)
        writers, exists = analyze_path(
            full, root_prefix=path_prefix, owner_override=owner_override
        )
        if not exists:
            findings.append(
                Finding(
                    code="READWRITE_PATH_MISSING",
                    severity=FindingSeverity.INFO,
                    message=f"ReadWritePaths entry does not exist yet: {expanded}",
                    target_path=expanded,
                    origin=origin,
                )
            )
            continue
        for writer in writers:
            findings.append(
                Finding(
                    code="READWRITE_PATH_EXPOSURE",
                    severity=FindingSeverity.INFO,
                    message=(
                        f"ReadWritePaths makes {expanded} writable; first non-root-writable "
                        f"component: {writer.principal} ({describe_mode(writer.mode)})"
                    ),
                    target_path=expanded,
                    component=writer.component,
                    principal=writer.principal,
                    mode=writer.mode,
                    origin=origin,
                )
            )
    return findings


def _prefixed(path: str, path_prefix: str) -> str:
    if not path_prefix:
        return path
    if path.startswith(path_prefix):
        return path
    return os.path.join(path_prefix, path.lstrip(os.path.sep))


def _build_owner_override(path_prefix: str) -> dict[str, tuple[int, int]]:
    """Treat every component inside a staged prefix as root-owned by default.

    Real vendor trees (``/usr``, ``/etc``) are owned by root; test staging
    directories are created by an unprivileged user. Callers can still make a
    component world/group-writable via its mode bits, which is what the
    writability checks primarily rely on.
    """
    if not path_prefix:
        return {}
    override: dict[str, tuple[int, int]] = {}
    current = os.path.abspath(path_prefix)
    while current and current != os.path.sep:
        override[current] = (0, 0)
        current = os.path.dirname(current)
    return override


def _dedupe_findings(findings: list[Finding]) -> list[Finding]:
    """Collapse identical (code, target/component/principal) observations."""
    seen: set[tuple] = set()
    unique: list[Finding] = []
    for finding in findings:
        key = (finding.code, finding.target_path, finding.component, finding.principal)
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique


