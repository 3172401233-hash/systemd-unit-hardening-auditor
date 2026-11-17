"""Minimal systemd preset evaluation (systemd.preset(5)).

Preset files only decide whether a unit is enabled by default; they never
change runtime hardening directives. They are included so an audit can point
at the preset file/line that governs ``systemctl preset`` behaviour.
"""

from __future__ import annotations

import fnmatch
import os

from .models import DirectiveOrigin, PresetDecision
from .parser import parse_preset_file

PRESET_DIRS = ("system-preset", "user-preset")


def evaluate_presets(search_roots: list[str], unit_name: str) -> PresetDecision | None:
    preset_files: list[str] = []
    for root in search_roots:
        parent = os.path.dirname(root.rstrip(os.sep)) or root
        for dirname in PRESET_DIRS:
            directory = os.path.join(parent, dirname)
            if not os.path.isdir(directory):
                continue
            for entry in sorted(os.listdir(directory)):
                if entry.endswith(".preset"):
                    preset_files.append(os.path.join(directory, entry))

    # Later files in lexicographic order override earlier ones.
    decisions: list[tuple[bool, str, DirectiveOrigin]] = []
    wildcard: tuple[bool, str, DirectiveOrigin] | None = None
    for path in sorted(preset_files):
        for action, pattern, rule_path, line in parse_preset_file(path):
            if not fnmatch.fnmatch(unit_name, pattern):
                continue
            origin = DirectiveOrigin(
                path=rule_path,
                section="preset",
                line=line,
                key=action,
                raw_value=pattern,
                kind="preset",
            )
            rule = (action == "enable", f"{action} {pattern}", origin)
            if pattern == "*":
                wildcard = rule
            else:
                decisions.append(rule)

    if not decisions:
        if wildcard is None:
            return PresetDecision(
                enabled=None,
                origin=None,
                matched_rule=None,
                preset_files=tuple(sorted(preset_files)),
            )
        enabled, rule, origin = wildcard
        return PresetDecision(
            enabled=enabled,
            origin=origin,
            matched_rule=rule,
            preset_files=tuple(sorted(preset_files)),
        )
    enabled, rule, origin = decisions[-1]
    return PresetDecision(
        enabled=enabled,
        origin=origin,
        matched_rule=rule,
        preset_files=tuple(sorted(preset_files)),
    )
