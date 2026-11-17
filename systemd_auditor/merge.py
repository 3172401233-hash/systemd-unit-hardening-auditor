"""Merge parsed unit/drop-in directives into effective values.

Merge rules follow systemd:
* scalar directives: last assignment wins;
* list directives: assignments append, an empty assignment resets the list;
* ``CapabilityBoundingSet`` has its own OR/AND/inversion state machine;
* every surviving value keeps the :class:`DirectiveOrigin` that set it.
"""

from __future__ import annotations

from .capabilities import CapabilityAccumulator
from .expansion import (
    expand_specifiers,
    normalize_private_tmp,
    normalize_protect_home,
    normalize_protect_system,
    split_path_tokens,
)
from .models import DirectiveOrigin, EffectiveConfig, EffectiveValue, ParsedFile

SERVICE_SECTION = "service"

SCALAR_KEYS = frozenset(
    {
        "User",
        "Group",
        "WorkingDirectory",
        "RootDirectory",
        "UMask",
        "Type",
        "PIDFile",
        "NotifyAccess",
        "DynamicUser",
        "NoNewPrivileges",
        "RestrictSUIDSGID",
        "RemoveIPC",
        "RestrictNamespaces",
        "RestrictRealtime",
        "LockPersonality",
        "MemoryDenyWriteExecute",
        "RestrictAddressFamilies",
        "SystemCallFilter",
        "SystemCallArchitectures",
        "Personality",
        "KeyringMode",
        "Delegate",
        "OOMScoreAdjust",
        "Nice",
        "CPUSchedulingPolicy",
        "IOSchedulingClass",
        "TimeoutStartSec",
        "TimeoutStopSec",
        "Restart",
    }
)

LIST_KEYS = frozenset(
    {
        "SupplementaryGroups",
        "ReadWritePaths",
        "ReadOnlyPaths",
        "InaccessiblePaths",
        "BindPaths",
        "BindReadOnlyPaths",
        "TemporaryFileSystem",
        "DeviceAllow",
        "IPAddressAllow",
        "IPAddressDeny",
        "SocketBindAllow",
        "SocketBindDeny",
        "RestrictNetworkInterfaces",
        "LoadCredential",
        "SetCredential",
    }
)

# Directives that may appear multiple times where each *line* (not each
# whitespace token) is one entry. Empty assignments still reset the list.
LINE_LIST_KEYS = frozenset(
    {
        "Environment",
        "EnvironmentFile",
        "ExecStart",
        "ExecStartPre",
        "ExecStartPost",
        "ExecReload",
        "ExecStop",
        "ExecStopPost",
    }
)

# Directives whose raw values need normalization when presented.
NORMALIZERS = {
    "ProtectSystem": normalize_protect_system,
    "ProtectHome": normalize_protect_home,
    "PrivateTmp": normalize_private_tmp,
}


def _origin_from(file: ParsedFile, section: str, key: str, value: str, line: int) -> DirectiveOrigin:
    return DirectiveOrigin(
        path=file.path,
        section=section,
        line=line,
        key=key,
        raw_value=value,
        kind=file.kind,
    )


class _ListState:
    def __init__(self) -> None:
        self.entries: list[object] = []
        self.origins: list[DirectiveOrigin] = []
        self.reset_origin: DirectiveOrigin | None = None

    def add(self, entry: object, origin: DirectiveOrigin) -> None:
        self.entries.append(entry)
        self.origins.append(origin)

    def reset(self) -> None:
        self.entries.clear()
        self.origins.clear()
        self.reset_origin = None


def merge_files(
    files: list[ParsedFile],
    unit_name: str | None = None,
    instance: str | None = None,
) -> EffectiveConfig:
    """Fold main unit + drop-ins (already in application order) together."""
    scalars: dict[tuple[str, str], EffectiveValue] = {}
    lists: dict[tuple[str, str], _ListState] = {}
    cap_acc = CapabilityAccumulator()
    cap_origins: list[DirectiveOrigin] = []

    for file in files:
        for item in file.lines:
            section = item.section
            key = item.key
            value = item.value
            origin = _origin_from(file, section, key, value, item.line)
            index = (section.lower(), key.lower())

            if (
                section.lower() == SERVICE_SECTION
                and key == "CapabilityBoundingSet"
            ):
                cap_acc.apply(value)
                cap_origins.append(origin)
                continue

            if key in LIST_KEYS or key in LINE_LIST_KEYS:
                state = lists.setdefault(index, _ListState())
                if value.strip() == "":
                    state.reset()
                    state.reset_origin = origin
                    continue
                if key in LINE_LIST_KEYS:
                    state.add(value.strip(), origin)
                elif key in ("ReadWritePaths", "ReadOnlyPaths", "InaccessiblePaths"):
                    for _prefix, path in split_path_tokens(value):
                        resolved = (
                            expand_specifiers(path, unit_name, instance)
                            if unit_name
                            else path
                        )
                        state.add(resolved, origin)
                else:
                    for token in value.split():
                        state.add(token, origin)
                continue

            if key in SCALAR_KEYS or key in NORMALIZERS:
                normalized = NORMALIZERS.get(key, lambda raw: raw)(value)
                scalars[index] = EffectiveValue(
                    key=key, section=section, value=normalized, origins=(origin,)
                )
                continue

            # Unknown directives behave as scalars (last assignment wins).
            scalars[index] = EffectiveValue(
                key=key, section=section, value=value, origins=(origin,)
            )

    result = EffectiveConfig(values=dict(scalars))
    for index, state in lists.items():
        origins = tuple(state.origins)
        if not state.entries and state.reset_origin is not None:
            origins = (state.reset_origin,)
        result.values[index] = EffectiveValue(
            key=_display_key(index),
            section=_display_section(index),
            value=tuple(state.entries),
            origins=origins,
        )
    if cap_origins:
        result.values[(SERVICE_SECTION.lower(), "capabilityboundingset")] = EffectiveValue(
            key="CapabilityBoundingSet",
            section="Service",
            value=tuple(sorted(cap_acc.effective() or ())),
            origins=tuple(cap_origins),
        )
    return result


def _display_key(index: tuple[str, str]) -> str:
    # Preserve canonical spelling for the keys we know about.
    for canonical in (*SCALAR_KEYS, *LIST_KEYS, *LINE_LIST_KEYS):
        if canonical.lower() == index[1]:
            return canonical
    return index[1]


def _display_section(index: tuple[str, str]) -> str:
    return {"service": "Service", "unit": "Unit", "install": "Install"}.get(
        index[0], index[0].capitalize()
    )
