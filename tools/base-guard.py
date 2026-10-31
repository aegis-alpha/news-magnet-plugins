#!/usr/bin/env python3
"""The pull-request check against the base branch: what the catalogue never lets a pull request do.
Python only, no other library; run from the catalogue's folder.

    base-guard.py --base <revision> [--head <revision>]

It refuses, as one line `refused <place>: <reason>` on stderr and exit 1:
- a pull request that changes `plugins/` or `index.json` together with anything else (a plugin
  submission and a change of the tools, workflows, keys or texts are separate pull requests);
- a file under `plugins/` that the base already has and the pull request changes, deletes or
  renames: a sealed archive never changes, a new version is a new file;
- an entry sealed on the base that the pull request removes, resets to unsealed, points at another
  archive hash or gives another archive address, so one kind and version never has two sealed
  archives;
- a path added under `plugins/` that is not `plugins/<kind>/<kind>-<version>.zip` of an entry in the
  pull request's index, or is not a regular file (git mode 100644: no link, no executable);
- an `index.json` that is not a regular file;
- an archive address (on an entry the pull request adds or changes) that is not empty and is not
  this repository's raw address `https://raw.githubusercontent.com/<owner>/<repo>/<branch>/plugins/
  <kind>/<kind>-<version>.zip`: archives are downloaded only from the catalogue repository itself.
  The repository comes from `--repository` (default: `GITHUB_REPOSITORY`), the branch from
  `--branch` (default: `GITHUB_BASE_REF`; none known: any branch name).

Otherwise it prints `scope: plugins` or `scope: tooling` and exits 0; inside GitHub Actions it also
writes `scope=<that>` to the step's outputs.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys

INDEX = "index.json"
PLUGINS = "plugins/"
REGULAR = "100644"


class Refused(Exception):
    def __init__(self, place: str, reason: str):
        super().__init__(f"{place}: {reason}")
        self.place = place
        self.reason = reason


def _git(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], capture_output=True, check=False)


def changes(base: str, head: str) -> list[tuple[str, str, str]]:
    """(status, path, new mode) of every file that differs; a rename is a delete and an add."""
    result = _git("diff", "--raw", "--no-abbrev", "--no-renames", "-z", base, head, "--")
    if result.returncode != 0:
        message = result.stderr.decode("utf-8", "replace").strip().splitlines()
        raise Refused("base", f"git cannot compare {base} with {head}: {' '.join(message)}")
    fields = result.stdout.decode("utf-8", "surrogateescape").split("\0")
    triples = []
    for info, path in zip(fields[0::2], fields[1::2]):  # noqa: B905 (strict= needs Python 3.10)
        parts = info.lstrip(":").split()
        if len(parts) >= 5:
            triples.append((parts[4][0], path, parts[1]))
    return triples


def is_plugin_change(path: str) -> bool:
    return path == INDEX or path.startswith(PLUGINS)


def scope_of(paths: list[str]) -> str:
    """`plugins` or `tooling`; a pull request that mixes the two is refused."""
    plugin = [p for p in paths if is_plugin_change(p)]
    other = [p for p in paths if not is_plugin_change(p)]
    if plugin and other:
        raise Refused(
            "scope",
            f"a plugin change ({plugin[0]}) and another change ({other[0]}) in one pull request",
        )
    return "plugins" if plugin else "tooling"


def check_plugins_path(triples: list[tuple[str, str, str]]) -> None:
    """`plugins` is a folder: a file or a link of that name (git lists it as a path of its own)
    would let the folder be replaced, so any change to it is refused."""
    for _status, path, _mode in triples:
        if path == PLUGINS.rstrip("/"):
            raise Refused(path, "plugins is a folder; a file or a link of that name is refused")


def check_types(head_entries: list) -> None:
    """kind, version and archive_url are texts; anything else is refused in one line."""
    for position, entry in enumerate(head_entries):
        if not isinstance(entry, dict):
            continue
        for name in ("kind", "version", "archive_url"):
            if name in entry and not isinstance(entry[name], str):
                raise Refused(f"entries[{position}].{name}", "a text is expected")


def check_files(triples: list[tuple[str, str, str]]) -> None:
    for status, path, _mode in triples:
        if path.startswith(PLUGINS) and status != "A":
            reason = "deleted" if status == "D" else "changed"
            raise Refused(path, f"a file the base branch has may not be {reason}")


def check_modes(triples: list[tuple[str, str, str]], head_entries: list) -> None:
    """Added paths under plugins/ are the entries' archives and regular files; index.json too."""
    expected = set()
    for entry in head_entries:
        pair = _pair(entry)
        if pair is not None:
            expected.add(f"{PLUGINS}{pair[0]}/{pair[0]}-{pair[1]}.zip")
    for status, path, mode in triples:
        if status == "D":
            continue
        if path == INDEX and mode != REGULAR:
            raise Refused(path, f"must be a regular file (git mode {REGULAR}), not {mode}")
        if path.startswith(PLUGINS):
            if path not in expected:
                raise Refused(
                    path,
                    "not the archive of an entry in index.json (plugins/<kind>/<kind>-<ver>.zip)",
                )
            if mode != REGULAR:
                raise Refused(path, f"must be a regular file (git mode {REGULAR}), not {mode}")


def check_addresses(base_entries: list, head_entries: list, repository: str, branch: str) -> None:
    """An address the pull request adds or changes is empty or this repository's raw address."""
    before = {}
    for entry in base_entries:
        pair = _pair(entry)
        if pair is not None and isinstance(entry, dict):
            before.setdefault(pair, set()).add(entry.get("archive_url"))
    for entry in head_entries:
        pair = _pair(entry)
        if pair is None or not isinstance(entry, dict):
            continue
        url = entry.get("archive_url")
        if url in before.get(pair, ()) or url == "" or url is None:
            continue
        place = f"{pair[0]}-{pair[1]}"
        refusal = (
            "archive_url must be empty or this repository's raw address "
            f"(https://raw.githubusercontent.com/{repository or '<repo>'}/<branch>/plugins/...)"
        )
        if not isinstance(url, str) or not repository:
            raise Refused(place, refusal)
        kind, version = re.escape(str(pair[0])), re.escape(str(pair[1]))
        branch_part = re.escape(branch) if branch else r"[^/?#\s][^?#\s]*?"
        pattern = (
            rf"https://(?i:raw\.githubusercontent\.com)/{re.escape(repository)}/{branch_part}"
            rf"/plugins/{kind}/{kind}-{version}\.zip"
        )
        if (
            "/../" in url
            or not url.isprintable()
            or any(c.isspace() or c in "%?#" for c in url)
            or not re.fullmatch(pattern, url)
        ):
            raise Refused(place, refusal)


def _index_at(revision: str) -> list:
    """The entries of `index.json` at `revision`; none when the file is not there."""
    if _git("cat-file", "-e", f"{revision}:{INDEX}").returncode != 0:
        return []
    shown = _git("show", f"{revision}:{INDEX}")
    try:
        top = json.loads(shown.stdout)
    except (ValueError, RecursionError):
        raise Refused(INDEX, f"not readable JSON at {revision}") from None
    entries = top.get("entries") if isinstance(top, dict) else None
    if not isinstance(entries, list):
        raise Refused(INDEX, f"no list of entries at {revision}")
    return entries


def _pair(entry: object) -> tuple[object, object] | None:
    if not isinstance(entry, dict):
        return None
    kind, version = entry.get("kind"), entry.get("version")
    if not isinstance(kind, str) or not isinstance(version, str):
        return None
    return kind, version


def _sealed(entry: dict) -> bool:
    return isinstance(entry.get("archive_sha256"), str) and entry["archive_sha256"] != ""


def check_entries(base_entries: list, head_entries: list) -> None:
    head = {}
    for entry in head_entries:
        pair = _pair(entry)
        if pair is not None:
            head.setdefault(pair, []).append(entry)
    for entry in base_entries:
        pair = _pair(entry)
        if pair is None or not _sealed(entry):
            continue
        place = f"{pair[0]}-{pair[1]}"
        found = head.get(pair, [])
        if not found:
            raise Refused(place, "a sealed entry may not disappear")
        for twin in found:
            if not _sealed(twin):
                raise Refused(place, "a sealed entry may not become unsealed")
            if twin["archive_sha256"] != entry["archive_sha256"]:
                raise Refused(place, "a sealed entry may not point at another archive")
            if twin.get("archive_url") != entry.get("archive_url"):
                raise Refused(place, "a sealed entry may not change its archive address")


def guard(base: str, head: str, repository: str = "", branch: str = "") -> str:
    triples = changes(base, head)
    check_plugins_path(triples)
    scope = scope_of([path for _, path, _ in triples])
    check_files(triples)
    base_entries, head_entries = _index_at(base), _index_at(head)
    check_types(head_entries)
    check_entries(base_entries, head_entries)
    check_modes(triples, head_entries)
    check_addresses(base_entries, head_entries, repository, branch)
    return scope


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="base-guard.py", description=__doc__.splitlines()[0])
    parser.add_argument("--base", required=True, help="the base branch's revision")
    parser.add_argument("--head", default="HEAD", help="the pull request's revision")
    parser.add_argument(
        "--repository",
        default=os.environ.get("GITHUB_REPOSITORY", ""),
        help="this repository as owner/name (default: GITHUB_REPOSITORY)",
    )
    parser.add_argument(
        "--branch",
        default=os.environ.get("GITHUB_BASE_REF", ""),
        help="the branch the archive addresses name (default: GITHUB_BASE_REF; none: any)",
    )
    args = parser.parse_args(argv)
    try:
        scope = guard(args.base, args.head, args.repository, args.branch)
    except Refused as exc:
        print(f"refused {exc.place}: {exc.reason}", file=sys.stderr)
        return 1
    print(f"scope: {scope}")
    output = os.environ.get("GITHUB_OUTPUT")
    if output:
        with open(output, "a", encoding="utf-8") as out:
            out.write(f"scope={scope}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
