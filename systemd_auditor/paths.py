"""File-system writability analysis used by the hardening auditor.

No ``systemctl`` or mount introspection happens here: ownership and mode bits
are read with :func:`os.stat` so the same logic works against a copied
directory tree in unit tests.
"""

from __future__ import annotations

import glob
import grp
import os
import pwd
import stat as stat_module
from dataclasses import dataclass


@dataclass(frozen=True)
class WritableComponent:
    component: str
    principal: str
    mode: int
    sticky: bool


def principal_name(uid: int, gid: int) -> str:
    try:
        owner = pwd.getpwuid(uid).pw_name
    except KeyError:
        owner = f"uid={uid}"
    try:
        group = grp.getgrgid(gid).gr_name
    except KeyError:
        group = f"gid={gid}"
    return f"{owner}:{group}"


def _component_writers(
    component: str,
    mode: int,
    uid: int,
    gid: int,
    is_dir: bool,
) -> list[WritableComponent]:
    sticky = bool(mode & stat_module.S_ISVTX)
    principal = principal_name(uid, gid)
    writers: list[WritableComponent] = []

    # In a sticky world-writable directory (/tmp style) only the owner of an
    # existing entry may rename or delete it, so such directories are not
    # replacement vectors for a file already owned by root.
    if is_dir and sticky:
        return writers
    if mode & stat_module.S_IWOTH:
        writers.append(WritableComponent(component, "other", mode, sticky))
    if mode & stat_module.S_IWGRP and gid != 0:
        writers.append(WritableComponent(component, f"group:{principal}", mode, sticky))
    if uid != 0 and mode & stat_module.S_IWUSR:
        writers.append(WritableComponent(component, f"user:{principal}", mode, sticky))
    return writers


def analyze_path(
    path: str,
    root_prefix: str = "",
    owner_override: dict[str, tuple[int, int]] | None = None,
) -> tuple[list[WritableComponent], bool]:
    """Walk every component of ``path`` and report non-root writable spots.

    Returns ``(writers, exists)``. Glob patterns are expanded best-effort and
    treated as non-existent when nothing matches.

    ``owner_override`` maps absolute paths to ``(uid, gid)`` tuples, allowing
    callers (and tests) to simulate root-owned vendor trees while running
    unprivileged against a staged copy of the filesystem.
    """
    if not path:
        return [], False
    if any(char in path for char in "*?["):
        matches = glob.glob(path)
        if not matches:
            return [], False
        writers: list[WritableComponent] = []
        for match in matches:
            writers.extend(analyze_path(match, root_prefix, owner_override)[0])
        return writers, True

    if not os.path.exists(path):
        return [], False

    overrides = owner_override or {}
    prefix_abs = os.path.abspath(root_prefix) if root_prefix else None
    writers = []
    current = os.path.sep
    components = [part for part in path.split(os.path.sep) if part]
    for index, part in enumerate(components):
        current = os.path.join(current, part) if index else os.path.sep + part
        absolute = os.path.abspath(current)
        if prefix_abs is not None and absolute == prefix_abs:
            # The staging root itself is outside the unit's real FS view.
            continue
        try:
            st = os.stat(current)
        except OSError:
            return writers, True
        if absolute in overrides:
            uid, gid = overrides[absolute]
        elif prefix_abs is not None and (
            absolute == prefix_abs or absolute.startswith(prefix_abs + os.path.sep)
        ):
            # Components inside the staged vendor tree default to root-owned.
            uid, gid = 0, 0
        else:
            uid, gid = st.st_uid, st.st_gid
        writers.extend(
            _component_writers(
                component=current,
                mode=st.st_mode,
                uid=uid,
                gid=gid,
                is_dir=stat_module.S_ISDIR(st.st_mode),
            )
        )

    deduped: dict[str, WritableComponent] = {}
    for writer in writers:
        deduped.setdefault(writer.principal, writer)
    return list(deduped.values()), True


def describe_mode(mode: int) -> str:
    return stat_module.filemode(mode)
