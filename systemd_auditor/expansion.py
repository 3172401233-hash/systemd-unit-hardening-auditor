"""Value normalization, specifier/env expansion and ExecStart parsing."""

from __future__ import annotations

import os
import re
import shlex

from .models import DirectiveOrigin, ExecCommand

BOOLEAN_TRUE = {"1", "yes", "true", "on", "y", "t"}
BOOLEAN_FALSE = {"0", "no", "false", "off", "n", "f"}

# Executable prefixes from systemd.service(5), Table 2. Order matters:
# multi-character prefixes must be checked before single-character ones.
EXEC_PREFIXES = ("!!", "!", "+", "-", ":", "@")

DEFAULT_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

_ENV_VAR = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)")


def parse_boolean(value: str) -> bool | None:
    """systemd boolean parsing; ``None`` for unrecognized values."""
    token = value.strip().lower()
    if token in BOOLEAN_TRUE:
        return True
    if token in BOOLEAN_FALSE:
        return False
    return None


def normalize_protect_system(value: str) -> str:
    boolean = parse_boolean(value)
    if boolean is True:
        return "full"
    if boolean is False:
        return "off"
    token = value.strip().lower()
    if token in ("full", "strict"):
        return token
    return token or "off"


def normalize_protect_home(value: str) -> str:
    boolean = parse_boolean(value)
    if boolean is True:
        return "tmpfs"
    if boolean is False:
        return "off"
    token = value.strip().lower()
    if token in ("read-only", "tmpfs"):
        return token
    return token or "off"


def normalize_private_tmp(value: str) -> str:
    boolean = parse_boolean(value)
    if boolean is True:
        return "yes"
    if boolean is False:
        return "no"
    return value.strip().lower()


def expand_specifiers(value: str, unit_name: str, instance: str | None) -> str:
    """Expand the subset of systemd specifiers resolvable without PID 1."""
    template, _, suffix = unit_name.partition("@")
    if suffix:
        instance_part = suffix.split(".", 1)[0]
    else:
        instance_part = ""
    prefix = unit_name.split(".", 1)[0]
    replacements = {
        "%n": unit_name,
        "%N": unit_name.replace("\\", "\\x5c"),
        "%p": template if "@" in unit_name else prefix,
        "%i": instance if instance is not None else instance_part,
        "%I": _unescape(instance if instance is not None else instance_part),
        "%g": str(os.getgid()),
        "%U": str(os.getuid()),
        "%u": _user_name(os.getuid()),
        "%%": "%",
    }
    result = value
    for token, replacement in replacements.items():
        result = result.replace(token, replacement)
    return result


def expand_env(value: str, environment: dict[str, str]) -> str:
    """Expand ``$VAR`` and ``${VAR}``; unknown variables are left intact."""

    def repl(match: re.Match[str]) -> str:
        name = match.group(1) or match.group(2)
        return environment.get(name, match.group(0))

    return _ENV_VAR.sub(repl, value)


def _unescape(value: str) -> str:
    """Reverse systemd's C-style path escaping (``\\x2d`` and friends)."""
    def repl(match: re.Match[str]) -> str:
        return chr(int(match.group(1), 16))

    return re.sub(r"\\x([0-9a-fA-F]{2})", repl, value)


def _user_name(uid: int) -> str:
    try:
        import pwd

        return pwd.getpwuid(uid).pw_name
    except (KeyError, ImportError):
        return str(uid)


def strip_exec_prefixes(raw: str) -> tuple[str, bool]:
    """Return ``(prefixes, ignore_failure)`` from an Exec command line."""
    prefixes = ""
    rest = raw.lstrip()
    changed = True
    while changed:
        changed = False
        for prefix in EXEC_PREFIXES:
            if rest.startswith(prefix):
                prefixes += prefix
                rest = rest[len(prefix) :].lstrip()
                changed = True
                break
    return prefixes, rest


def parse_exec_command(
    directive: str,
    raw_value: str,
    origin: DirectiveOrigin,
    environment: dict[str, str],
    unit_name: str,
    instance: str | None,
    path_value: str | None = None,
) -> ExecCommand:
    """Parse one Exec* line into an :class:`ExecCommand`."""
    expanded = expand_env(expand_specifiers(raw_value, unit_name, instance), environment)
    prefixes, command_line = strip_exec_prefixes(expanded)
    ignore_failure = "-" in prefixes
    try:
        argv = tuple(shlex.split(command_line))
    except ValueError:
        argv = tuple(command_line.split())
    executable: str | None = None
    if argv:
        executable = resolve_executable(argv[0], path_value)
    return ExecCommand(
        directive=directive,
        argv=argv,
        executable=executable,
        prefixes=prefixes,
        ignore_failure=ignore_failure,
        origin=origin,
    )


def resolve_executable(program: str, path_value: str | None = None) -> str:
    """Resolve relative programs against ``$PATH`` (systemd service default)."""
    if not program:
        return program
    if program.startswith("/"):
        return program
    if "/" in program:
        # Relative path with a slash is resolved from WorkingDirectory,
        # which we cannot know statically; return it untouched.
        return program
    search_path = path_value or DEFAULT_PATH
    for directory in search_path.split(":"):
        candidate = os.path.join(directory, program)
        if os.path.isfile(candidate):
            return candidate
    return os.path.join(search_path.split(":", 1)[0], program)


def split_path_tokens(raw_value: str) -> list[tuple[str, str]]:
    """Split ReadWritePaths-style values into ``(prefix, path)`` pairs."""
    tokens: list[tuple[str, str]] = []
    for token in raw_value.split():
        prefix = ""
        path = token
        while path[:1] in ("-", "+", "~", ":"):
            prefix += path[0]
            path = path[1:]
        tokens.append((prefix, path))
    return tokens
