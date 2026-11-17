"""Pure-Python systemd unit hardening auditor.

The library parses main unit files and their drop-in directories, merges the
directives exactly the way systemd does (lexicographic drop-in order, reset
semantics for empty assignments, ...) and reports the *effective* hardening
settings together with the file/section that made them effective.

It never talks to ``systemctl`` or the service manager: every analysis is
performed against files on disk that the caller points it at.
"""

from .audit import audit_unit
from .loader import load_unit
from .models import (
    AuditReport,
    DirectiveOrigin,
    EffectiveValue,
    ExecCommand,
    Finding,
    LoadedUnit,
    ParsedFile,
    ParsedLine,
    PresetDecision,
)

__all__ = [
    "audit_unit",
    "load_unit",
    "AuditReport",
    "DirectiveOrigin",
    "EffectiveValue",
    "ExecCommand",
    "Finding",
    "LoadedUnit",
    "ParsedFile",
    "ParsedLine",
    "PresetDecision",
]

__version__ = "1.0.0"
