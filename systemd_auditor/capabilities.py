"""CapabilityBoundingSet merge logic (systemd.exec(5) semantics).

* un-prefixed assignments are merged with logical OR;
* ``~`` prefixed assignments invert against the full set and merge with AND;
* an empty assignment (``CapabilityBoundingSet=``) resets to the empty set;
* a bare ``~`` resets to the full capability set.
"""

from __future__ import annotations

import re

# CAP_LAST_CAP on mainstream kernels is much lower; this generous list covers
# every capability defined by current Linux so inverted sets stay deterministic.
CAPABILITY_NAMES: tuple[str, ...] = (
    "CAP_CHOWN",
    "CAP_DAC_OVERRIDE",
    "CAP_DAC_READ_SEARCH",
    "CAP_FOWNER",
    "CAP_FSETID",
    "CAP_KILL",
    "CAP_SETGID",
    "CAP_SETUID",
    "CAP_SETPCAP",
    "CAP_LINUX_IMMUTABLE",
    "CAP_NET_BIND_SERVICE",
    "CAP_NET_BROADCAST",
    "CAP_NET_ADMIN",
    "CAP_NET_RAW",
    "CAP_IPC_LOCK",
    "CAP_IPC_OWNER",
    "CAP_SYS_MODULE",
    "CAP_SYS_RAWIO",
    "CAP_SYS_CHROOT",
    "CAP_SYS_PTRACE",
    "CAP_SYS_PACCT",
    "CAP_SYS_ADMIN",
    "CAP_SYS_BOOT",
    "CAP_SYS_NICE",
    "CAP_SYS_RESOURCE",
    "CAP_SYS_TIME",
    "CAP_SYS_TTY_CONFIG",
    "CAP_MKNOD",
    "CAP_LEASE",
    "CAP_AUDIT_WRITE",
    "CAP_AUDIT_CONTROL",
    "CAP_SETFCAP",
    "CAP_MAC_OVERRIDE",
    "CAP_MAC_ADMIN",
    "CAP_SYSLOG",
    "CAP_WAKE_ALARM",
    "CAP_BLOCK_SUSPEND",
    "CAP_AUDIT_READ",
    "CAP_PERFMON",
    "CAP_BPF",
    "CAP_CHECKPOINT_RESTORE",
)

FULL_SET: frozenset[str] = frozenset(CAPABILITY_NAMES)
EMPTY_SET: frozenset[str] = frozenset()

_NUMERIC = re.compile(r"^(\d+)$")


def normalize_capability(token: str) -> str:
    """Accept ``CAP_FOO``, ``foo`` or numeric forms, return canonical name."""
    token = token.strip()
    upper = token.upper()
    if upper in FULL_SET:
        return upper
    match = _NUMERIC.match(token)
    if match:
        index = int(match.group(1))
        if 0 <= index < len(CAPABILITY_NAMES):
            return CAPABILITY_NAMES[index]
        return f"CAP_{index}"
    if not upper.startswith("CAP_"):
        upper = "CAP_" + upper
    return upper


class CapabilityAccumulator:
    """Stateful merge of successive CapabilityBoundingSet assignments."""

    def __init__(self) -> None:
        # None means "never assigned", i.e. systemd applies no bounding limit.
        self.current: frozenset[str] | None = None

    def apply(self, raw_value: str) -> frozenset[str] | None:
        value = raw_value.strip()
        if value == "":
            # Empty assignment resets to the *empty* set.
            self.current = EMPTY_SET
            return self.current

        inverted = value.startswith("~")
        body = value[1:].strip() if inverted else value
        tokens = body.split()
        parsed = {normalize_capability(token) for token in tokens}

        if inverted:
            if not parsed:
                # Bare "~" resets to the full set.
                self.current = FULL_SET
            else:
                assignment = FULL_SET - parsed
                self.current = assignment if self.current is None else (self.current & assignment)
        else:
            self.current = parsed if self.current is None else (self.current | parsed)
        return self.current

    def effective(self) -> frozenset[str] | None:
        return self.current
