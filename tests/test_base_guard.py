"""The pull-request check against the base branch (`tools/base-guard.py`), run as a subprocess in a
temporary git repository: a base commit holding the good sample catalogue, then one pull request's
change per test."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
GUARD = HERE.parent / "tools" / "base-guard.py"
GOOD = HERE / "fixtures" / "good-two-seals"
FEED_ZIP = "plugins/sample_feed/sample_feed-1.0.0.zip"
WIRE_ZIP = "plugins/sample_wire/sample_wire-2.0.0.zip"


def git(repo: Path, *args: str) -> str:
    env = {
        **os.environ,
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_AUTHOR_NAME": "tester",
        "GIT_AUTHOR_EMAIL": "tester@example.com",
        "GIT_COMMITTER_NAME": "tester",
        "GIT_COMMITTER_EMAIL": "tester@example.com",
    }
    result = subprocess.run(
        ["git", *args], cwd=repo, capture_output=True, text=True, env=env, check=True
    )
    return result.stdout


@pytest.fixture
def repo(tmp_path) -> Path:
    """A catalogue with the good sample committed on `base`, checked out on `change`."""
    root = tmp_path / "catalogue"
    shutil.copytree(GOOD, root)
    (root / "README.md").write_text("catalogue\n", encoding="utf-8")
    git(root, "init", "-q", "-b", "base")
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "base")
    git(root, "checkout", "-q", "-b", "change")
    return root


def index(repo: Path) -> dict:
    return json.loads((repo / "index.json").read_text(encoding="utf-8"))


def write_index(repo: Path, top: dict) -> None:
    (repo / "index.json").write_text(json.dumps(top, indent=2) + "\n", encoding="utf-8")


REPOSITORY = "acme/plugins"
OWN = (
    "https://raw.githubusercontent.com/acme/plugins/main/plugins/sample_feed/sample_feed-1.1.0.zip"
)


def guard(repo: Path, tmp_path: Path, *extra: str) -> tuple[int, str | None, str | None]:
    """Commit the change and run the guard: exit code, refused place, scope written to outputs."""
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "--allow-empty", "-m", "change")
    output = tmp_path / "github-output"
    output.write_text("", encoding="utf-8")
    env = {**os.environ, "GITHUB_OUTPUT": str(output), "GITHUB_REPOSITORY": REPOSITORY}
    env.pop("GITHUB_BASE_REF", None)
    result = subprocess.run(
        [sys.executable, str(GUARD), "--base", "base", "--head", "HEAD", *extra],
        cwd=repo,
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
    )
    place = None
    if result.returncode:
        match = re.match(r"refused (\S+): ", result.stderr)
        assert match, result.stderr
        place = match.group(1)
    scope = re.findall(r"^scope=(\w+)$", output.read_text(encoding="utf-8"), re.M)
    return result.returncode, place, scope[0] if scope else None


def add_submission(repo: Path, version: str = "1.1.0") -> None:
    data = (repo / FEED_ZIP).read_bytes()
    (repo / f"plugins/sample_feed/sample_feed-{version}.zip").write_bytes(data)
    top = index(repo)
    entry = {**top["entries"][0], "version": version}
    entry.update(archive_sha256="", seals=[], archive_url="")
    top["entries"].append(entry)
    write_index(repo, top)


def test_a_new_plugin_with_its_unsealed_entry_passes_as_a_plugin_change(repo, tmp_path):
    add_submission(repo)
    assert guard(repo, tmp_path) == (0, None, "plugins")


def test_a_tooling_change_alone_passes_as_tooling(repo, tmp_path):
    (repo / "README.md").write_text("catalogue, better said\n", encoding="utf-8")
    (repo / "tools").mkdir()
    (repo / "tools" / "x.py").write_text("print()\n", encoding="utf-8")
    assert guard(repo, tmp_path) == (0, None, "tooling")


def test_a_plugin_mixed_with_another_change_is_refused(repo, tmp_path):
    add_submission(repo)
    (repo / "README.md").write_text("catalogue, better said\n", encoding="utf-8")
    assert guard(repo, tmp_path)[:2] == (1, "scope")


def test_an_index_edit_mixed_with_a_key_change_is_refused(repo, tmp_path):
    top = index(repo)
    top["entries"][0]["withdrawn"] = True
    write_index(repo, top)
    (repo / "keys.pub").write_text("# no keys\n", encoding="utf-8")
    assert guard(repo, tmp_path)[:2] == (1, "scope")


def test_a_withdrawal_passes(repo, tmp_path):
    top = index(repo)
    top["entries"][0]["withdrawn"] = True
    write_index(repo, top)
    assert guard(repo, tmp_path) == (0, None, "plugins")


def test_a_changed_archive_is_refused(repo, tmp_path):
    (repo / FEED_ZIP).write_bytes((repo / FEED_ZIP).read_bytes() + b"\0")
    assert guard(repo, tmp_path)[:2] == (1, FEED_ZIP)


def test_a_deleted_archive_is_refused_even_with_its_entry_gone(repo, tmp_path):
    (repo / WIRE_ZIP).unlink()
    top = index(repo)
    top["entries"] = top["entries"][:1]
    write_index(repo, top)
    assert guard(repo, tmp_path)[:2] == (1, WIRE_ZIP)


def test_a_renamed_archive_is_refused(repo, tmp_path):
    git(repo, "mv", FEED_ZIP, "plugins/sample_feed/sample_feed-1.0.1.zip")
    assert guard(repo, tmp_path)[:2] == (1, FEED_ZIP)


def test_a_sealed_entry_that_disappears_is_refused(repo, tmp_path):
    top = index(repo)
    top["entries"] = top["entries"][1:]
    write_index(repo, top)
    assert guard(repo, tmp_path)[:2] == (1, "sample_feed-1.0.0")


def test_a_sealed_entry_reset_to_unsealed_is_refused(repo, tmp_path):
    top = index(repo)
    top["entries"][1].update(archive_sha256="", seals=[], archive_url="")
    write_index(repo, top)
    assert guard(repo, tmp_path)[:2] == (1, "sample_wire-2.0.0")


def test_a_sealed_entry_pointing_at_another_archive_is_refused(repo, tmp_path):
    top = index(repo)
    top["entries"][0]["archive_sha256"] = "0" * 64
    write_index(repo, top)
    assert guard(repo, tmp_path)[:2] == (1, "sample_feed-1.0.0")


def test_a_second_entry_for_a_sealed_version_reset_to_unsealed_is_refused(repo, tmp_path):
    top = index(repo)
    twin = {**top["entries"][0], "archive_sha256": "", "seals": [], "archive_url": ""}
    top["entries"].append(twin)
    write_index(repo, top)
    assert guard(repo, tmp_path)[:2] == (1, "sample_feed-1.0.0")


def test_an_archive_on_the_base_never_goes_away_even_unsealed(repo, tmp_path):
    add_submission(repo)
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "submission merged")
    git(repo, "branch", "-f", "base", "HEAD")
    (repo / "plugins/sample_feed/sample_feed-1.1.0.zip").unlink()
    top = index(repo)
    top["entries"] = top["entries"][:2]
    write_index(repo, top)
    assert guard(repo, tmp_path)[:2] == (1, "plugins/sample_feed/sample_feed-1.1.0.zip")


def test_an_unsealed_entry_on_the_base_may_be_dropped_from_the_index(repo, tmp_path):
    add_submission(repo)
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "submission merged")
    git(repo, "branch", "-f", "base", "HEAD")
    top = index(repo)
    top["entries"] = top["entries"][:2]
    write_index(repo, top)
    assert guard(repo, tmp_path) == (0, None, "plugins")


def test_a_base_without_an_index_passes(repo, tmp_path):
    git(repo, "rm", "-q", "index.json")
    git(repo, "commit", "-q", "-m", "no index")
    git(repo, "branch", "-f", "base", "HEAD")
    write_index(repo, {"format_version": 1, "entries": []})
    assert guard(repo, tmp_path) == (0, None, "plugins")


def test_an_unreadable_index_on_the_head_is_refused(repo, tmp_path):
    (repo / "index.json").write_text("{not json", encoding="utf-8")
    assert guard(repo, tmp_path)[:2] == (1, "index.json")


def test_an_unknown_base_revision_is_refused(repo, tmp_path):
    git(repo, "branch", "-D", "base")
    assert guard(repo, tmp_path)[:2] == (1, "base")


def set_url(repo: Path, url: str, version: str = "1.1.0") -> None:
    add_submission(repo, version)
    top = index(repo)
    top["entries"][-1]["archive_url"] = url
    write_index(repo, top)


def test_an_empty_archive_address_passes(repo, tmp_path):
    set_url(repo, "")
    assert guard(repo, tmp_path) == (0, None, "plugins")


def test_this_repositorys_raw_address_passes(repo, tmp_path):
    set_url(repo, OWN)
    assert guard(repo, tmp_path) == (0, None, "plugins")
    assert guard(repo, tmp_path, "--branch", "main") == (0, None, "plugins")


def test_this_repositorys_raw_address_on_another_branch_is_refused_when_the_branch_is_known(
    repo, tmp_path
):
    set_url(repo, OWN.replace("/main/", "/other/"))
    assert guard(repo, tmp_path, "--branch", "main")[:2] == (1, "sample_feed-1.1.0")


def test_an_address_on_another_host_is_refused(repo, tmp_path):
    set_url(repo, "https://example.com/plugins/sample_feed/sample_feed-1.1.0.zip")
    assert guard(repo, tmp_path)[:2] == (1, "sample_feed-1.1.0")


def test_an_address_in_another_repository_is_refused(repo, tmp_path):
    set_url(repo, OWN.replace("acme/plugins", "acme/other"))
    assert guard(repo, tmp_path)[:2] == (1, "sample_feed-1.1.0")


def test_an_address_that_climbs_out_of_the_repository_is_refused(repo, tmp_path):
    set_url(repo, OWN.replace("/main/", "/main/../../evil/x/"))
    assert guard(repo, tmp_path)[:2] == (1, "sample_feed-1.1.0")


def test_without_a_known_repository_only_an_empty_address_passes(repo, tmp_path):
    set_url(repo, OWN)
    add = guard(repo, tmp_path, "--repository", "")
    assert add[:2] == (1, "sample_feed-1.1.0")


def test_a_changed_address_on_a_sealed_entry_is_refused(repo, tmp_path):
    top = index(repo)
    top["entries"][0]["archive_url"] = (
        "https://raw.githubusercontent.com/acme/plugins/main/plugins/sample_feed/sample_feed-1.0.0.zip"
    )
    write_index(repo, top)
    assert guard(repo, tmp_path)[:2] == (1, "sample_feed-1.0.0")


def test_an_unchanged_address_on_a_sealed_entry_passes(repo, tmp_path):
    top = index(repo)
    top["entries"][0]["withdrawn"] = True
    write_index(repo, top)
    assert guard(repo, tmp_path) == (0, None, "plugins")


def test_an_added_archive_with_the_executable_bit_is_refused(repo, tmp_path):
    add_submission(repo)
    path = repo / "plugins/sample_feed/sample_feed-1.1.0.zip"
    path.chmod(0o755)
    assert guard(repo, tmp_path)[:2] == (1, "plugins/sample_feed/sample_feed-1.1.0.zip")


def test_an_added_archive_that_is_a_symlink_is_refused(repo, tmp_path):
    add_submission(repo)
    path = repo / "plugins/sample_feed/sample_feed-1.1.0.zip"
    path.unlink()
    path.symlink_to("sample_feed-1.0.0.zip")
    assert guard(repo, tmp_path)[:2] == (1, "plugins/sample_feed/sample_feed-1.1.0.zip")


def test_a_stray_path_under_plugins_is_refused(repo, tmp_path):
    add_submission(repo)
    (repo / "plugins/sample_feed/notes.txt").write_text("x\n", encoding="utf-8")
    assert guard(repo, tmp_path)[:2] == (1, "plugins/sample_feed/notes.txt")


def test_an_archive_without_an_entry_in_the_index_is_refused(repo, tmp_path):
    (repo / "plugins/sample_feed/sample_feed-3.0.0.zip").write_bytes(b"x")
    assert guard(repo, tmp_path)[:2] == (1, "plugins/sample_feed/sample_feed-3.0.0.zip")


def test_an_index_that_is_a_symlink_is_refused(repo, tmp_path):
    (repo / "index.json").unlink()
    (repo / "index.json").symlink_to("keys.pub")
    assert guard(repo, tmp_path)[:2] == (1, "index.json")


def test_a_link_named_plugins_in_place_of_the_folder_is_refused(repo, tmp_path):
    shutil.rmtree(repo / "plugins")
    (repo / "plugins").symlink_to("/")
    assert guard(repo, tmp_path)[:2] == (1, "plugins")


def test_a_file_named_plugins_is_refused(repo, tmp_path):
    shutil.rmtree(repo / "plugins")
    (repo / "plugins").write_text("x\n", encoding="utf-8")
    assert guard(repo, tmp_path)[:2] == (1, "plugins")


@pytest.mark.parametrize("name", ["kind", "version", "archive_url"])
@pytest.mark.parametrize("value", [["x"], {"x": 1}])
def test_a_list_or_an_object_in_a_text_field_is_a_one_line_refusal(repo, tmp_path, name, value):
    add_submission(repo)
    top = index(repo)
    top["entries"][-1][name] = value
    write_index(repo, top)
    git(repo, "add", "-A")
    code, place, _scope = guard(repo, tmp_path)
    assert (code, place) == (1, f"entries[{len(top['entries']) - 1}].{name}")
