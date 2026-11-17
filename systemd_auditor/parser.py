"""Parsing of systemd unit files, drop-in files and environment files.

Only syntax-level work happens here: no merging, no specifier expansion.
Line continuations and comments follow systemd.syntax(7).
"""

from __future__ import annotations

import os
import shlex

from .models import ParsedFile, ParsedLine


def parse_unit_file(path: str, kind: str = "main") -> ParsedFile:
    """Parse a single unit/drop-in file into ordered directive lines."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            text = handle.read()
    except OSError as exc:
        return ParsedFile(path=path, kind=kind, parse_errors=(f"unreadable: {exc}",))

    lines: list[ParsedLine] = []
    errors: list[str] = []
    section = ""
    logical_parts: list[str] = []
    logical_start = 0

    def flush(end_line: int) -> None:
        if not logical_parts:
            return
        content = "".join(logical_parts)
        logical_parts.clear()
        stripped = content.strip()
        if not stripped or stripped.startswith(("#", ";")):
            return
        if "=" not in stripped:
            errors.append(f"{path}:{end_line}: directive missing '=': {stripped!r}")
            return
        key, value = stripped.split("=", 1)
        key = key.strip()
        if not key:
            errors.append(f"{path}:{end_line}: empty directive key")
            return
        lines.append(
            ParsedLine(section=section, key=key, value=value.strip(), line=logical_start)
        )

    for lineno, raw in enumerate(text.splitlines(), start=1):
        stripped = raw.strip()
        if not stripped or stripped.startswith(("#", ";")):
            continue
        if stripped.startswith(("[", "]")) and stripped.endswith("]"):
            flush(lineno - 1)
            section = stripped[1:-1].strip()
            continue
        if raw.rstrip("\r\n").endswith("\\"):
            if not logical_parts:
                logical_start = lineno
            logical_parts.append(raw.rstrip("\r\n")[:-1])
            continue
        if logical_parts:
            logical_parts.append(raw)
            flush(lineno)
        else:
            logical_start = lineno
            logical_parts.append(raw)
            flush(lineno)
    flush(-1)

    return ParsedFile(path=path, kind=kind, lines=tuple(lines), parse_errors=tuple(errors))


def parse_env_file(path: str) -> tuple[dict[str, str], tuple[str, ...]]:
    """Parse a systemd EnvironmentFile.

    Returns the variables and parse warnings. Quoted values are handled with
    :func:`shlex` so ``KEY="a b"`` works like systemd's parser.
    """
    env: dict[str, str] = {}
    warnings: list[str] = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            lines = handle.read().splitlines()
    except OSError as exc:
        return env, (f"{path}: unreadable: {exc}",)

    for lineno, raw in enumerate(lines, start=1):
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].lstrip()
        if "=" not in line:
            warnings.append(f"{path}:{lineno}: cannot parse environment line")
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        try:
            tokens = shlex.split(value, comments=True)
        except ValueError as exc:
            warnings.append(f"{path}:{lineno}: bad quoting: {exc}")
            continue
        if not key:
            warnings.append(f"{path}:{lineno}: empty variable name")
            continue
        env[key] = " ".join(tokens) if tokens else ""
    return env, tuple(warnings)


def parse_preset_file(path: str) -> list[tuple[str, str, str, int]]:
    """Parse one preset file into ``(action, pattern, path, line)`` tuples."""
    rules: list[tuple[str, str, str, int]] = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            for lineno, raw in enumerate(handle, start=1):
                line = raw.strip()
                if not line or line.startswith(("#", ";")):
                    continue
                parts = line.split()
                if len(parts) < 2 or parts[0] not in ("enable", "disable"):
                    continue
                rules.append((parts[0], parts[1], path, lineno))
    except OSError:
        return rules
    return rules


def collect_unit_files(
    search_roots: list[str],
    unit_name: str,
    template_name: str | None,
) -> tuple[str | None, tuple[str, ...], tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    """Locate main file, drop-in dirs, drop-in files and masks on disk.

    Returns ``(main_path, main_candidates, dropin_dirs, dropin_paths, masks)``.
    """
    # Literal instance name wins; if absent, fall back to the template file.
    main_name_variants = [unit_name]
    if template_name and template_name != unit_name:
        main_name_variants.append(template_name)
    main_candidates = [
        os.path.join(root, name)
        for name in main_name_variants
        for root in search_roots
    ]
    main_path: str | None = next(
        (candidate for candidate in main_candidates if os.path.isfile(candidate)
         or os.path.islink(candidate)),
        None,
    )

    # Drop-in directory groups, highest precedence first: instance name,
    # template name (for instantiated units).
    name_variants: list[str] = [unit_name]
    if template_name and template_name != unit_name:
        name_variants.append(template_name)

    dropin_dirs: list[str] = []
    for root in search_roots:
        for variant in name_variants:
            dropin_dirs.append(os.path.join(root, variant + ".d"))

    # Tuple: (basename, variant_index, root_priority_index, full_path)
    # systemd applies differently named drop-ins in lexicographic order
    # regardless of directory; only equally named files fall back to
    # directory (/etc > /run > /usr/lib) and instance > template precedence.
    candidates: list[tuple[str, int, int, str]] = []
    masks: list[str] = []
    for root_index, root in enumerate(search_roots):
        for variant_index, variant in enumerate(name_variants):
            directory = os.path.join(root, variant + ".d")
            if not os.path.isdir(directory):
                continue
            for entry in sorted(os.listdir(directory)):
                full = os.path.join(directory, entry)
                if os.path.islink(full) and os.readlink(full) == "/dev/null":
                    # A drop-in symlinked to /dev/null masks that file name.
                    masks.append(full)
                    continue
                if entry.endswith(".conf") and os.path.isfile(full):
                    candidates.append((entry, variant_index, root_index, full))

    candidates.sort(key=lambda item: (item[0], item[1], item[2]))
    dropin_paths: list[str] = []
    seen_names: set[str] = set()
    for basename, _, _, full in candidates:
        if basename in seen_names:
            continue
        seen_names.add(basename)
        dropin_paths.append(full)

    # A /dev/null main file means the unit is masked.
    if main_path is not None and os.path.islink(main_path) and os.readlink(main_path) == "/dev/null":
        masks.insert(0, main_path)

    return (
        main_path,
        tuple(main_candidates),
        tuple(dropin_dirs),
        tuple(dropin_paths),
        tuple(masks),
    )
