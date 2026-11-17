"""On-disk loading of a unit (or template instance) and its drop-ins."""

from __future__ import annotations

from .models import LoadedUnit, PresetDecision
from .parser import collect_unit_files, parse_unit_file
from .preset import evaluate_presets

# First match wins for the main unit; drop-in precedence is independent.
DEFAULT_SEARCH_ROOTS = (
    "/etc/systemd/system",
    "/run/systemd/system",
    "/usr/local/lib/systemd/system",
    "/usr/lib/systemd/system",
)


def split_template(unit_name: str) -> tuple[str | None, str | None]:
    """Return ``(template_name, instance)`` for ``name@instance.type``."""
    base = unit_name.split(".", 1)[0]
    if "@" not in base:
        return None, None
    template_base, instance = base.split("@", 1)
    suffix = unit_name.split(".", 1)[1] if "." in unit_name else ""
    template_name = template_base + "@." + suffix if suffix else template_base + "@"
    return template_name, instance or None


def load_unit(
    unit_name: str,
    search_roots: list[str] | tuple[str, ...] | None = None,
) -> LoadedUnit:
    """Load every file contributing to ``unit_name`` without running systemd."""
    roots = list(search_roots) if search_roots is not None else list(DEFAULT_SEARCH_ROOTS)
    template_name, instance = split_template(unit_name)

    main_path, main_candidates, dropin_dirs, dropin_paths, masks = collect_unit_files(
        roots, unit_name, template_name
    )

    main_file = parse_unit_file(main_path, kind="main") if main_path else None
    dropins = tuple(parse_unit_file(path, kind="dropin") for path in dropin_paths)
    preset = evaluate_presets(roots, unit_name)

    return LoadedUnit(
        unit_name=unit_name,
        template_name=template_name,
        instance=instance,
        main_file=main_file,
        main_candidates=main_candidates,
        dropin_dirs=dropin_dirs,
        dropins=dropins,
        preset=preset or PresetDecision(None, None, None),
        search_roots=tuple(roots),
        mask_paths=masks,
    )


def unit_exists(loaded: LoadedUnit) -> bool:
    return loaded.main_file is not None or bool(loaded.dropins)


def effective_files(loaded: LoadedUnit) -> tuple[str, ...]:
    """Files in actual application order (main first, then sorted drop-ins)."""
    paths: list[str] = []
    if loaded.main_file is not None:
        paths.append(loaded.main_file.path)
    paths.extend(dropin.path for dropin in loaded.dropins)
    return tuple(paths)
