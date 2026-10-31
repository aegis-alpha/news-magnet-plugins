"""The signing tool, run as a subprocess with throwaway keys made in each test.

Needs Python, `cryptography` and `pytest`; run with `python -m pytest tests` from the catalogue's
folder."""

import base64
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import warnings
import zipfile
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

HERE = Path(__file__).resolve().parent
TOOL = HERE.parent / "tools" / "catalogue-sign.py"
FIXTURES = HERE / "fixtures"
GOOD = FIXTURES / "good-two-seals"
CASES = json.loads((FIXTURES / "cases.json").read_text(encoding="utf-8"))
FEED = ("sample_feed", "1.0.0")
URL_BASE = "https://raw.githubusercontent.com/owner/repo/main/"


class Pair:
    """A throwaway key pair: `seed` is the private line, `line` the public key line."""

    def __init__(self) -> None:
        private = Ed25519PrivateKey.generate()
        raw = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.seed = base64.b64encode(private.private_bytes_raw()).decode()
        self.line = "ed25519 " + base64.b64encode(raw).decode()
        self.fingerprint = hashlib.sha256(raw).hexdigest()[:16]


def run(*args, keys: list[str] | None = None) -> subprocess.CompletedProcess:
    env = {name: value for name, value in os.environ.items() if name != "CATALOGUE_SIGNING_KEYS"}
    if keys is not None:
        env["CATALOGUE_SIGNING_KEYS"] = "\n".join(keys) + "\n"
    command = [sys.executable, str(TOOL), *map(str, args)]
    return subprocess.run(command, capture_output=True, text=True, env=env, timeout=60)


def refused_at(result: subprocess.CompletedProcess) -> str | None:
    """The place a refusal names, or None when the tool passed."""
    if result.returncode == 0:
        return None
    match = re.match(r"refused (\S+): ", result.stderr)
    assert match, result.stderr
    return match.group(1)


def entry_of(kind: str, version: str, **changes) -> dict:
    """An unsealed entry for an archive of the good fixture."""
    good = {(e["kind"], e["version"]): e for e in _index(GOOD)["entries"]}[(kind, version)]
    return {**good, "archive_sha256": "", "seals": [], "archive_url": "", **changes}


def _index(folder: Path) -> dict:
    return json.loads((folder / "index.json").read_text(encoding="utf-8"))


def workspace(tmp_path: Path, *entries: dict, pairs: tuple[Pair, ...] = ()) -> Path:
    """A catalogue folder: the good fixture's archives, an index of `entries`, a keys file."""
    root = tmp_path / "catalogue"
    shutil.copytree(GOOD / "plugins", root / "plugins")
    (root / "index.json").write_text(
        json.dumps({"format_version": 1, "entries": list(entries)}), encoding="utf-8"
    )
    write_keys(root, *pairs)
    return root


def write_keys(root: Path, *pairs: Pair) -> None:
    text = "# throwaway keys\n" + "".join(p.line + "\n" for p in pairs)
    (root / "keys.pub").write_text(text, encoding="utf-8")


def tool(command: str, root: Path, *extra, keys: list[str] | None = None):
    args = [command, root / "index.json"]
    if command != "drop-seals":
        args += ["--root", root, "--keys", root / "keys.pub"]
    if command == "seal":
        args += ["--url-base", URL_BASE]
    return run(*args, *extra, keys=keys)


def check(root: Path, *extra) -> subprocess.CompletedProcess:
    return tool("check", root, *extra)


# ---- new-key -------------------------------------------------------------------------------------


def test_new_key_writes_the_private_line_alone_with_mode_0600(tmp_path):
    path = tmp_path / "catalogue.key"
    result = run("new-key", path)
    assert result.returncode == 0, result.stderr
    assert path.stat().st_mode & 0o777 == 0o600
    seed = path.read_text(encoding="utf-8").strip()
    private = Ed25519PrivateKey.from_private_bytes(base64.b64decode(seed, validate=True))
    raw = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    line = "ed25519 " + base64.b64encode(raw).decode()
    assert result.stdout.splitlines() == [
        line,
        f"fingerprint {hashlib.sha256(raw).hexdigest()[:16]}",
    ]
    assert seed not in result.stdout and seed not in result.stderr


def test_new_key_refuses_an_existing_path(tmp_path):
    path = tmp_path / "catalogue.key"
    path.write_text("kept\n", encoding="utf-8")
    result = run("new-key", path)
    assert refused_at(result) == "path"
    assert path.read_text(encoding="utf-8") == "kept\n"


def test_new_key_refuses_a_path_inside_a_git_working_copy(tmp_path):
    (tmp_path / "repo" / ".git").mkdir(parents=True)
    (tmp_path / "repo" / "keys").mkdir()
    path = tmp_path / "repo" / "keys" / "catalogue.key"
    result = run("new-key", path)
    assert refused_at(result) == "path"
    assert not path.exists()


# ---- seal ----------------------------------------------------------------------------------------


def test_seal_without_a_key_and_an_unsealed_entry_writes_nothing(tmp_path):
    root = workspace(tmp_path, entry_of(*FEED), pairs=(Pair(),))
    before = (root / "index.json").read_bytes()
    result = tool("seal", root)
    assert refused_at(result) == "key"
    assert (root / "index.json").read_bytes() == before


def test_seal_with_nothing_unsealed_exits_0_without_a_key_and_changes_nothing(tmp_path):
    root = tmp_path / "catalogue"
    shutil.copytree(GOOD, root)
    before = (root / "index.json").read_bytes()
    result = tool("seal", root)
    assert result.returncode == 0, result.stderr
    assert (root / "index.json").read_bytes() == before


def test_seal_then_check_passes(tmp_path):
    pair = Pair()
    root = workspace(tmp_path, entry_of(*FEED), pairs=(pair,))
    assert refused_at(check(root)) == "entries[0]"
    assert check(root, "--allow-unsealed").returncode == 0
    result = tool("seal", root, keys=[pair.seed])
    assert result.returncode == 0, result.stderr
    assert pair.seed not in result.stdout + result.stderr
    entry = _index(root)["entries"][0]
    archive = root / "plugins" / "sample_feed" / "sample_feed-1.0.0.zip"
    assert entry["archive_sha256"] == hashlib.sha256(archive.read_bytes()).hexdigest()
    assert entry["archive_url"] == (URL_BASE + "plugins/sample_feed/sample_feed-1.0.0.zip")
    assert [seal["key"] for seal in entry["seals"]] == [pair.fingerprint]
    assert check(root).returncode == 0


def test_seal_keeps_an_archive_url_already_given(tmp_path):
    pair = Pair()
    url = "https://raw.githubusercontent.com/o/r/main/plugins/sample_feed/sample_feed-1.0.0.zip"
    root = workspace(tmp_path, entry_of(*FEED, archive_url=url), pairs=(pair,))
    assert tool("seal", root, keys=[pair.seed]).returncode == 0
    assert _index(root)["entries"][0]["archive_url"] == url


def test_seal_with_two_keys_gives_two_seals(tmp_path):
    old, new = Pair(), Pair()
    root = workspace(tmp_path, entry_of(*FEED), pairs=(old, new))
    # Two lines and a blank one in the environment.
    result = tool("seal", root, keys=[old.seed, "", new.seed])
    assert result.returncode == 0, result.stderr
    seals = _index(root)["entries"][0]["seals"]
    assert [seal["key"] for seal in seals] == [old.fingerprint, new.fingerprint]
    assert check(root).returncode == 0
    write_keys(root, new)
    assert refused_at(check(root)) == "entries[0].seals[0]"


def test_seal_reads_key_files_beside_the_environment(tmp_path):
    old, new = Pair(), Pair()
    root = workspace(tmp_path, entry_of(*FEED), pairs=(old, new))
    key_file = tmp_path / "new.key"
    key_file.write_text(new.seed + "\n", encoding="utf-8")
    result = tool("seal", root, "--key-file", key_file, keys=[old.seed])
    assert result.returncode == 0, result.stderr
    seals = _index(root)["entries"][0]["seals"]
    assert [seal["key"] for seal in seals] == [old.fingerprint, new.fingerprint]


def test_seal_refuses_a_key_missing_from_the_keys_file(tmp_path):
    listed, stray = Pair(), Pair()
    root = workspace(tmp_path, entry_of(*FEED), pairs=(listed,))
    before = (root / "index.json").read_bytes()
    result = tool("seal", root, keys=[listed.seed, stray.seed])
    assert refused_at(result) == "key"
    assert stray.fingerprint in result.stderr and stray.seed not in result.stderr
    assert (root / "index.json").read_bytes() == before


def test_seal_refuses_an_archive_whose_manifest_differs_and_writes_nothing(tmp_path):
    pair = Pair()
    root = workspace(tmp_path, entry_of(*FEED, paid=True), pairs=(pair,))
    before = (root / "index.json").read_bytes()
    result = tool("seal", root, keys=[pair.seed])
    assert refused_at(result) == "entries[0].manifest.paid"
    assert (root / "index.json").read_bytes() == before


def test_seal_leaves_sealed_entries_alone(tmp_path):
    root = tmp_path / "catalogue"
    shutil.copytree(GOOD, root)
    wire = next(e for e in _index(root)["entries"] if e["kind"] == "sample_wire")
    pair = Pair()
    with (root / "keys.pub").open("a", encoding="utf-8") as keys:
        keys.write(pair.line + "\n")
    index = {"format_version": 1, "entries": [wire, entry_of(*FEED)]}
    (root / "index.json").write_text(json.dumps(index), encoding="utf-8")
    assert tool("seal", root, keys=[pair.seed]).returncode == 0
    entries = _index(root)["entries"]
    assert entries[0] == wire
    assert [seal["key"] for seal in entries[1]["seals"]] == [pair.fingerprint]
    assert check(root).returncode == 0


# ---- key change: add-seals and drop-seals --------------------------------------------------------


def test_add_seals_then_drop_seals_moves_every_entry_to_the_new_key(tmp_path):
    old, new = Pair(), Pair()
    root = workspace(tmp_path, entry_of(*FEED), entry_of("sample_wire", "2.0.0"), pairs=(old,))
    assert tool("seal", root, keys=[old.seed]).returncode == 0
    assert refused_at(tool("add-seals", root)) == "key"
    write_keys(root, old, new)
    result = tool("add-seals", root, keys=[new.seed])
    assert result.returncode == 0, result.stderr
    assert new.seed not in result.stdout + result.stderr
    for entry in _index(root)["entries"]:
        assert [seal["key"] for seal in entry["seals"]] == [old.fingerprint, new.fingerprint]
    assert check(root).returncode == 0
    # Run again: the new key's seal is replaced, never doubled.
    assert tool("add-seals", root, keys=[new.seed]).returncode == 0
    assert check(root).returncode == 0

    result = run("drop-seals", root / "index.json", "--fingerprint", old.fingerprint)
    assert result.returncode == 0, result.stderr
    for entry in _index(root)["entries"]:
        assert [seal["key"] for seal in entry["seals"]] == [new.fingerprint]
    write_keys(root, new)
    assert check(root).returncode == 0


def test_add_seals_refuses_a_changed_archive(tmp_path):
    old, new = Pair(), Pair()
    root = workspace(tmp_path, entry_of(*FEED), pairs=(old, new))
    assert tool("seal", root, keys=[old.seed]).returncode == 0
    archive = root / "plugins" / "sample_feed" / "sample_feed-1.0.0.zip"
    archive.write_bytes(archive.read_bytes() + b"\0")
    before = (root / "index.json").read_bytes()
    assert refused_at(tool("add-seals", root, keys=[new.seed])) == "entries[0].archive_sha256"
    assert (root / "index.json").read_bytes() == before


def test_drop_seals_that_would_leave_an_entry_with_none_is_refused(tmp_path):
    only = Pair()
    root = workspace(tmp_path, entry_of(*FEED), pairs=(only,))
    assert tool("seal", root, keys=[only.seed]).returncode == 0
    before = (root / "index.json").read_bytes()
    result = run("drop-seals", root / "index.json", "--fingerprint", only.fingerprint)
    assert refused_at(result) == "entries[0].seals"
    assert (root / "index.json").read_bytes() == before


# ---- the path rule -------------------------------------------------------------------------------


@pytest.mark.parametrize("version", ["../x", "a/b", "a\\b", ".hidden"])
def test_a_version_that_is_not_one_plain_file_name_is_refused(tmp_path, version):
    root = workspace(tmp_path, {**entry_of(*FEED), "version": version}, pairs=(Pair(),))
    assert refused_at(check(root, "--allow-unsealed")) == "entries[0].version"


def test_an_archive_that_is_a_link_outside_plugins_is_never_read(tmp_path):
    pair = Pair()
    root = workspace(tmp_path, entry_of(*FEED), pairs=(pair,))
    archive = root / "plugins" / "sample_feed" / "sample_feed-1.0.0.zip"
    outside = tmp_path / "outside.zip"
    shutil.move(archive, outside)
    archive.symlink_to(outside)
    outside.chmod(0o000)  # reading it would fail loudly, not as a refusal
    try:
        result = tool("seal", root, keys=[pair.seed])
        assert refused_at(result) == "entries[0].archive"
        assert "symbolic link" in result.stderr
        assert refused_at(check(root, "--allow-unsealed")) == "entries[0].archive"
    finally:
        outside.chmod(0o644)


def test_a_kind_folder_that_is_a_link_is_refused(tmp_path):
    root = workspace(tmp_path, entry_of(*FEED), pairs=(Pair(),))
    elsewhere = tmp_path / "elsewhere"
    shutil.move(root / "plugins" / "sample_feed", elsewhere)
    (root / "plugins" / "sample_feed").symlink_to(elsewhere, target_is_directory=True)
    assert refused_at(check(root, "--allow-unsealed")) == "entries[0].archive"


# ---- archive members (the service refuses the same at install) ----------------------------------


def _feed_manifest() -> bytes:
    with zipfile.ZipFile(GOOD / "plugins" / "sample_feed" / "sample_feed-1.0.0.zip") as zf:
        return zf.read("manifest.json")


def _member(name: str, mode: int | None = None) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, (2026, 10, 31, 0, 0, 0))
    if mode is not None:
        info.create_system = 3
        info.external_attr = mode << 16
    return info


def _encrypted(data: bytes, name: str) -> bytes:
    """`data` with `name` marked encrypted (bit 0 of the flags, in both headers): zipfile cannot
    write an encrypted member itself."""
    out = bytearray(data)
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        info = zf.getinfo(name)
    out[info.header_offset + 6] |= 0x1
    position = 0
    while (position := out.find(b"PK\x01\x02", position)) != -1:
        length = int.from_bytes(out[position + 28 : position + 30], "little")
        if bytes(out[position + 46 : position + 46 + length]) == name.encode():
            out[position + 8] |= 0x1
        position += 4
    return bytes(out)


def _zip(*members: tuple[zipfile.ZipInfo | str, bytes]) -> bytes:
    buf = io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")  # a duplicate name on purpose
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("manifest.json", _feed_manifest())
            for info, data in members:
                zf.writestr(info, data)
    return buf.getvalue()


UNSAFE_ARCHIVES = {
    "parent": lambda: _zip(("../evil.py", b"x")),
    "absolute": lambda: _zip(("/etc/evil.py", b"x")),
    "backslash": lambda: _zip(("a\\evil.py", b"x")),
    "drive": lambda: _zip(("C:evil.py", b"x")),
    "symlink": lambda: _zip((_member("link", 0o120777), b"/etc/passwd")),
    "device": lambda: _zip((_member("dev", 0o020644), b"")),
    "encrypted": lambda: _encrypted(_zip(("secret.py", b"x")), "secret.py"),
    "duplicate": lambda: _zip(("plugin.py", b"a"), ("plugin.py", b"b")),
    "file-and-folder": lambda: _zip(("lib", b"x"), ("lib/mod.py", b"y")),
    "too-many": lambda: _zip(*((f"m{n}.txt", b"") for n in range(500))),
    "too-large-unpacked": lambda: _zip(("big.bin", bytes(50 * 1024 * 1024 + 1))),
}


def _with_archive(tmp_path: Path, data: bytes) -> Path:
    root = workspace(tmp_path, entry_of(*FEED), pairs=(Pair(),))
    (root / "plugins" / "sample_feed" / "sample_feed-1.0.0.zip").write_bytes(data)
    return root


@pytest.mark.parametrize("name", sorted(UNSAFE_ARCHIVES))
def test_an_unsafe_archive_is_neither_sealed_nor_passed(tmp_path, name):
    pair = Pair()
    root = _with_archive(tmp_path, UNSAFE_ARCHIVES[name]())
    write_keys(root, pair)
    before = (root / "index.json").read_bytes()
    assert refused_at(tool("seal", root, keys=[pair.seed])) == "entries[0].archive"
    assert (root / "index.json").read_bytes() == before
    assert refused_at(check(root, "--allow-unsealed")) == "entries[0].archive"


def test_a_safe_archive_with_folders_and_500_members_passes(tmp_path):
    members = [("lib/", b""), ("lib/mod.py", b"y")]
    members += [(f"m{n}.txt", b"") for n in range(497)]
    root = _with_archive(tmp_path, _zip(*members))
    assert check(root, "--allow-unsealed").returncode == 0


def test_a_corrupt_member_is_one_refusal_line_not_a_crash(tmp_path):
    data = bytearray(_zip())
    with zipfile.ZipFile(io.BytesIO(bytes(data))) as zf:
        info = zf.getinfo("manifest.json")
    start = info.header_offset + 30 + len(info.filename.encode()) + len(info.extra)
    for offset in range(start, start + info.compress_size):
        data[offset] = 0xFF
    root = _with_archive(tmp_path, bytes(data))
    result = check(root, "--allow-unsealed")
    assert refused_at(result) == "entries[0].archive"
    assert result.stderr.count("\n") == 1 and "Traceback" not in result.stderr


# ---- the keys file -------------------------------------------------------------------------------


_P = 2**255 - 19


def _y(value: int, sign: int = 0) -> bytes:
    return (value | sign << 255).to_bytes(32, "little")


_ORDER_8 = bytes.fromhex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a")


@pytest.mark.parametrize(
    "raw",
    [
        _y(1),  # the identity
        bytes(32),  # all zero: an order-4 point
        _y(_P - 1),  # order 2
        _ORDER_8,
        _y(1, sign=1),  # the identity with the sign bit set
        _y(2),  # no curve point
    ],
    ids=["identity", "all-zero", "order-2", "order-8", "identity-signed", "off-curve"],
)
def test_a_small_order_or_off_curve_key_line_is_refused(tmp_path, raw):
    root = tmp_path / "catalogue"
    shutil.copytree(GOOD, root)
    keys = (root / "keys.pub").read_text(encoding="utf-8")
    line = "ed25519 " + base64.b64encode(raw).decode()
    (root / "keys.pub").write_text(keys + line + "\n", encoding="utf-8")
    number = len(keys.splitlines()) + 1
    assert refused_at(check(root)) == f"keys[{number}]"


def test_a_malformed_key_line_is_refused_with_its_number(tmp_path):
    root = tmp_path / "catalogue"
    shutil.copytree(GOOD, root)
    (root / "keys.pub").write_text("# keys\n\nssh-ed25519 AAAA\n", encoding="utf-8")
    assert refused_at(check(root)) == "keys[3]"


# ---- the fixtures --------------------------------------------------------------------------------


@pytest.mark.parametrize("name", sorted(CASES))
def test_every_fixture_gives_its_expected_result(name):
    case, folder = CASES[name], FIXTURES / name
    args = ["check", folder / "index.json", "--root", folder, "--keys", folder / "keys.pub"]
    if case.get("allow_unsealed"):
        args.append("--allow-unsealed")
    result = run(*args)
    assert (result.returncode, refused_at(result)) == (case["exit"], case["field"]), result.stderr


def test_the_good_fixture_passes_the_strict_check_with_one_archive_per_entry():
    result = run("check", GOOD / "index.json", "--root", GOOD, "--keys", GOOD / "keys.pub")
    assert result.returncode == 0, result.stderr
    entries = _index(GOOD)["entries"]
    assert sorted(len(entry["seals"]) for entry in entries) == [1, 2]
    archives = sorted(p.relative_to(GOOD).as_posix() for p in GOOD.rglob("*.zip"))
    assert archives == sorted(
        f"plugins/{e['kind']}/{e['kind']}-{e['version']}.zip" for e in entries
    )


_BARE_KEY = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{43}=(?![A-Za-z0-9+/=])")


def _texts(path: Path):
    if path.suffix == ".zip":
        with zipfile.ZipFile(path) as zf:
            for name in zf.namelist():
                yield f"{path}:{name}", zf.read(name).decode("utf-8", "replace")
    else:
        yield str(path), path.read_text(encoding="utf-8", errors="replace")


def test_no_fixture_holds_a_bare_32_byte_value_a_private_key_would_look_like():
    found = []
    for path in sorted(p for p in FIXTURES.rglob("*") if p.is_file()):
        for where, text in _texts(path):
            for match in _BARE_KEY.finditer(text):
                before = text[max(0, match.start() - 8) : match.start()]
                if len(base64.b64decode(match.group())) == 32 and before != "ed25519 ":
                    found.append(where)
    assert found == []


# ---- archive addresses (rows 74 and 75) ----------------------------------------------------------


def _sealed_with_url(tmp_path, url):
    pair = Pair()
    root = workspace(tmp_path, entry_of(*FEED), pairs=(pair,))
    assert tool("seal", root, keys=[pair.seed]).returncode == 0
    top = _index(root)
    top["entries"][0]["archive_url"] = url
    (root / "index.json").write_text(json.dumps(top), encoding="utf-8")
    return root


BAD_HOSTS = [
    "https://example.com/plugins/sample_feed/sample_feed-1.0.0.zip",
    "https://raw.githubusercontent.com.evil.example/o/r/main/plugins/x.zip",
    "https://x@raw.githubusercontent.com/o/r/main/plugins/x.zip",
    "https://raw.githubusercontent.com:8443/o/r/main/plugins/x.zip",
    "http://raw.githubusercontent.com/o/r/main/plugins/x.zip",
    "https://raw.githubusercontent.com",
    "https://raw.githubusercontent.com/o/r/a\t.zip",
    "https://raw.githubusercontent.com/o/r/a\r\n.zip",
]


@pytest.mark.parametrize("url", BAD_HOSTS)
def test_check_refuses_an_address_on_another_host(tmp_path, url):
    root = _sealed_with_url(tmp_path, url)
    assert refused_at(check(root)) == "entries[0].archive_url"


def test_check_with_a_repository_accepts_only_its_raw_address_on_the_branch(tmp_path):
    own = "https://raw.githubusercontent.com/acme/plugins/main/plugins/sample_feed/sample_feed-1.0.0.zip"
    root = _sealed_with_url(tmp_path, own)
    assert check(root).returncode == 0
    assert check(root, "--repository", "acme/plugins", "--branch", "main").returncode == 0
    for repository, branch in (("acme/other", "main"), ("acme/plugins", "dev")):
        result = check(root, "--repository", repository, "--branch", branch)
        assert refused_at(result) == "entries[0].archive_url"


def test_check_with_a_repository_refuses_a_sealed_entry_of_another_repository(tmp_path):
    root = _sealed_with_url(tmp_path, URL_BASE + "plugins/sample_feed/sample_feed-1.0.0.zip")
    result = check(root, "--repository", "acme/plugins", "--branch", "main")
    assert refused_at(result) == "entries[0].archive_url"


def test_check_with_a_repository_refuses_an_unsealed_entry_of_another_repository(tmp_path):
    url = URL_BASE + "plugins/sample_feed/sample_feed-1.0.0.zip"
    root = workspace(tmp_path, entry_of(*FEED, archive_url=url), pairs=(Pair(),))
    plain = check(root, "--allow-unsealed")
    assert plain.returncode == 0, plain.stderr
    result = check(root, "--allow-unsealed", "--repository", "acme/plugins", "--branch", "main")
    assert refused_at(result) == "entries[0].archive_url"


def test_check_wants_the_repository_and_the_branch_together(tmp_path):
    root = _sealed_with_url(tmp_path, URL_BASE + "plugins/sample_feed/sample_feed-1.0.0.zip")
    assert refused_at(check(root, "--repository", "owner/repo")) == "check"


OWN = (
    "https://raw.githubusercontent.com/acme/plugins/main/plugins/sample_feed/sample_feed-1.0.0.zip"
)


@pytest.mark.parametrize(
    "url",
    [
        OWN.replace("sample_feed-1.0.0", "other-1.0.0"),
        OWN.replace("sample_feed-1.0.0", "sample_feed-2.0.0"),
        OWN.replace("/main/", "/main/../dev/"),
        OWN + "?token=1",
        OWN + "#top",
        OWN.replace("1.0.0.zip", "1.0.0%2e.zip"),
        OWN + " ",
        OWN.replace("/plugins/sample_feed/", "/plugins/sample_feed/ "),
        OWN + "\n",
        OWN.replace("plugins/main", "plugins/main\t"),
        OWN.replace("sample_feed/sample", "sample_feed//sample"),
        OWN.replace("/acme/", "/ACME/"),
    ],
)
def test_check_with_a_repository_wants_the_exact_address_of_the_entry(tmp_path, url):
    root = _sealed_with_url(tmp_path, url)
    result = check(root, "--repository", "acme/plugins", "--branch", "main")
    assert refused_at(result) == "entries[0].archive_url"


def test_check_with_a_repository_accepts_the_exact_address_and_any_case_of_the_host(tmp_path):
    for number, url in enumerate(
        (OWN, OWN.replace("raw.githubusercontent.com", "RAW.GithubUserContent.com"))
    ):
        root = _sealed_with_url(tmp_path / str(number), url)
        assert check(root, "--repository", "acme/plugins", "--branch", "main").returncode == 0


def test_check_previous_exempts_only_entries_sealed_before(tmp_path):
    other = OWN.replace("/main/", "/dev/")
    root = _sealed_with_url(tmp_path, other)
    scope = ("--repository", "acme/plugins", "--branch", "main")
    assert refused_at(check(root, *scope)) == "entries[0].archive_url"
    sealed_before = tmp_path / "before.json"
    sealed_before.write_text((root / "index.json").read_text(encoding="utf-8"), encoding="utf-8")
    assert check(root, *scope, "--previous", str(sealed_before)).returncode == 0
    top = _index(root)
    top["entries"][0].update(archive_sha256="", seals=[])
    unsealed_before = tmp_path / "unsealed.json"
    unsealed_before.write_text(json.dumps(top), encoding="utf-8")
    result = check(root, *scope, "--previous", str(unsealed_before))
    assert refused_at(result) == "entries[0].archive_url"


def _previous_of(root, tmp_path, **changes):
    """A copy of the index as it was before, with `changes` made to its only entry."""
    top = _index(root)
    top["entries"][0].update(changes)
    before = tmp_path / "before.json"
    before.write_text(json.dumps(top), encoding="utf-8")
    return str(before)


SCOPE = ("--repository", "acme/plugins", "--branch", "main")


def test_check_previous_keeps_only_the_branch_of_an_entry_free(tmp_path):
    other = OWN.replace("/main/", "/dev/")
    root = _sealed_with_url(tmp_path, other)
    before = _previous_of(root, tmp_path)
    assert check(root, *SCOPE, "--previous", before).returncode == 0


@pytest.mark.parametrize(
    "url",
    [
        OWN.replace("/acme/", "/evil/").replace("/main/", "/dev/"),
        OWN.replace("/main/", "/dev/").replace("sample_feed-1.0.0", "other-1.0.0"),
        OWN.replace("/main/", "/dev/").replace("/plugins/sample_feed/", "/x/sample_feed/"),
        OWN.replace("/main/", "/dev/..%2f"),
        OWN.replace("/main/", "/dev/../"),
    ],
)
def test_check_previous_still_wants_the_repository_and_the_path(tmp_path, url):
    root = _sealed_with_url(tmp_path, url)
    before = _previous_of(root, tmp_path)
    assert refused_at(check(root, *SCOPE, "--previous", before)) == "entries[0].archive_url"


def test_check_previous_with_another_address_or_hash_is_not_exempt(tmp_path):
    root = _sealed_with_url(tmp_path, OWN.replace("/main/", "/dev/"))
    sealed_url = _previous_of(root, tmp_path, archive_url=OWN.replace("/main/", "/old/"))
    assert refused_at(check(root, *SCOPE, "--previous", sealed_url)) == "entries[0].archive_url"
    sealed_sha = _previous_of(root, tmp_path, archive_sha256="0" * 64)
    assert refused_at(check(root, *SCOPE, "--previous", sealed_sha)) == "entries[0].archive_url"


def test_check_previous_needs_the_repository(tmp_path):
    root = _sealed_with_url(tmp_path, OWN)
    result = check(root, "--previous", str(root / "index.json"))
    assert refused_at(result) == "check"


def test_an_address_with_a_control_character_is_refused_before_it_is_parsed(tmp_path):
    urls = (
        OWN.replace("main", "m\tain"),
        OWN.replace("com/", "com/\r\n"),
        OWN.replace("acme", "a\x00b"),
    )
    for number, url in enumerate(urls):
        root = _sealed_with_url(tmp_path / str(number), url)
        assert refused_at(check(root)) == "entries[0].archive_url"
