"""Shared helpers for building staged systemd trees in temporary directories."""

from __future__ import annotations

import os
import tempfile

from systemd_auditor.audit import audit_unit


class StagedTree:
    """A tiny filesystem layout mirroring /etc/systemd/system + /usr + /etc."""

    def __init__(self) -> None:
        self.root = tempfile.mkdtemp(prefix="auditor-test-")
        self.unit_root = os.path.join(self.root, "etc", "systemd", "system")
        os.makedirs(self.unit_root, exist_ok=True)

    def write(self, relative_path: str, content: str, mode: int | None = None) -> str:
        full = os.path.join(self.root, relative_path)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w", encoding="utf-8") as handle:
            handle.write(content)
        if mode is not None:
            os.chmod(full, mode)
        return full

    def unit(self, name: str, content: str) -> str:
        return self.write(os.path.join("etc/systemd/system", name), content)

    def dropin(self, unit_name: str, conf_name: str, content: str) -> str:
        return self.write(
            os.path.join("etc/systemd/system", unit_name + ".d", conf_name), content
        )

    def preset(self, file_name: str, content: str) -> str:
        return self.write(os.path.join("etc/systemd", "system-preset", file_name), content)

    def executable(self, relative_path: str, mode: int = 0o755) -> str:
        full = self.write(relative_path, "#!/bin/sh\nexit 0\n")
        os.chmod(full, mode)
        return full

    def chmod(self, relative_path: str, mode: int) -> None:
        os.chmod(os.path.join(self.root, relative_path), mode)

    def chown_running_user(self, relative_path: str) -> None:
        os.chown(os.path.join(self.root, relative_path), os.getuid(), os.getgid())

    def non_root_owner(self, relative_path: str, gid: int | None = None) -> None:
        """Mark a path as owned by an unprivileged uid/gid (simulation)."""
        full = os.path.join(self.root, relative_path)
        if not hasattr(self, "owner_overrides"):
            self.owner_overrides = {}
        self.owner_overrides[os.path.abspath(full)] = (
            os.getuid(),
            os.getgid() if gid is None else gid,
        )

    def audit(self, unit_name: str):
        return audit_unit(
            unit_name,
            search_roots=[self.unit_root],
            path_prefix=self.root,
            owner_override=getattr(self, "owner_overrides", None),
        )

    def cleanup(self) -> None:
        import shutil

        shutil.rmtree(self.root, ignore_errors=True)
