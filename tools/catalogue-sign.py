#!/usr/bin/env python3
"""The catalogue's signing tool: makes the signing key, seals accepted plugins and checks the
index strictly. It needs only Python and `cryptography`.

    catalogue-sign.py new-key <path>
    catalogue-sign.py seal <index.json> --root <dir> --url-base <raw base> --keys <pub file>
    catalogue-sign.py add-seals <index.json> --root <dir> --keys <pub file>
    catalogue-sign.py drop-seals <index.json> --fingerprint <hex>
    catalogue-sign.py check <index.json> --root <dir> --keys <pub file> [--allow-unsealed]
                           [--repository <owner/repo> --branch <name> [--previous <index>]]

`check` refuses an archive address on any host but `raw.githubusercontent.com`, or with whitespace
or a control character. With `--repository` and `--branch` it also refuses an address that is not
exactly `https://raw.githubusercontent.com/<repo>/<branch>/plugins/<kind>/<kind>-<version>.zip`
of that entry (no `..`, `%`, `?`, `#`). With `--previous <index>` (the sealing step: the index as
it was before the run) an entry sealed in that index with the same address and hash may name
another branch of the same repository (the path stays exact); any other entry, and an entry whose
address or hash changed, must carry this branch's address.

A seal is Ed25519 over four lines: `news-magnet-catalogue-seal-v1`, the kind, the version and the
archive's SHA-256. The rest of an entry is bound through the archive: `check` reads the manifest
inside it and refuses an entry that differs from it in kind, version, range, key or price.

Public keys (`--keys`): lines `ed25519 <base64 of the raw 32-byte key>`; `#` comments and blank
lines are ignored; a fingerprint is the first 16 hex digits of SHA-256 over the 32 bytes. A key
that names no curve point or a small-order one is refused.

Private keys: one line each, base64 of the raw 32-byte seed, read from the environment variable
`CATALOGUE_SIGNING_KEYS` (several lines; blank lines ignored) and from `--key-file <path>` (may be
repeated). `seal` and `add-seals` seal with every key given. A private key is never printed,
logged or written anywhere but `new-key`'s path.

An entry's archive is exactly `<root>/plugins/<kind>/<kind>-<version>.zip`; a path leaving that
folder, a symbolic link or a missing file is refused and never read. Inside the archive the tool
refuses what every server refuses at install: an unsafe member name (`..`, an absolute path, a
backslash), a link or device member, an encrypted or repeated member, a file that is also a
folder, more than 500 members or more than 50 MB unpacked.

A refusal is one line on stderr, `refused <place>: <reason>`, and exit 1; `<place>` is a path in
the index (`entries[2].version`, `entries[0].manifest.paid`) or a key line (`keys[3]`).
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import io
import json
import os
import re
import stat
import sys
import tempfile
import zipfile
import zlib
from datetime import date
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

FORMAT_VERSION = 1
SEAL_LABEL = "news-magnet-catalogue-seal-v1"
KEYS_ENV = "CATALOGUE_SIGNING_KEYS"
TEXT_LIMITS = {"title": 80, "description": 200, "notes": 500}
REQUIRED = (
    "kind",
    "title",
    "description",
    "version",
    "archive_url",
    "archive_sha256",
    "seals",
    "needs_key",
    "paid",
)
OPTIONAL = ("notes", "service_min", "service_max", "withdrawn")
MANIFEST_FIELDS = ("kind", "version", "service_min", "service_max", "needs_key", "paid")
ARCHIVE_MAX_BYTES = 5 * 1024 * 1024
MANIFEST_MAX_BYTES = 256 * 1024
MAX_MEMBERS = 500
UNPACKED_MAX_BYTES = 50 * 1024 * 1024

_KIND = re.compile(r"[a-z][a-z0-9_]{1,39}")
_VERSION = re.compile(r"[!-~]{1,40}")
_LANGUAGE = re.compile(r"[a-z]{2}")
_FINGERPRINT = re.compile(r"[0-9a-f]{16}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_RELEASE = re.compile(r"release-(\d{4}-\d{2}-\d{2})(?:-(\d+))?")
_DRIVE = re.compile(r"^[A-Za-z]:")


class Refused(Exception):
    def __init__(self, place: str, reason: str):
        super().__init__(f"{place}: {reason}")
        self.place = place
        self.reason = reason


# ---- keys ----------------------------------------------------------------------------------------

# Edwards25519 (RFC 8032): -x^2 + y^2 = 1 + d x^2 y^2 over GF(p).
_P = 2**255 - 19
_D = -121665 * pow(121666, _P - 2, _P) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def _decoded_point(raw: bytes) -> tuple[int, int, int, int] | None:
    """The point a 32-byte encoding names (extended coordinates), or None. Lenient like the
    verifier it guards: y at or above p is reduced, a sign bit on x = 0 is ignored."""
    number = int.from_bytes(raw, "little")
    sign = number >> 255
    y = (number & ((1 << 255) - 1)) % _P
    u = (y * y - 1) % _P
    v = (_D * y * y + 1) % _P
    x = u * pow(v, 3, _P) * pow(u * pow(v, 7, _P), (_P - 5) // 8, _P) % _P
    if (v * x * x - u) % _P != 0:
        x = x * _SQRT_M1 % _P
    if (v * x * x - u) % _P != 0:
        return None
    if x & 1 != sign:
        x = (_P - x) % _P
    return (x, y, 1, x * y % _P)


def _double(point: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    x, y, z, _ = point
    a, b = x * x % _P, y * y % _P
    c = 2 * z * z % _P
    h = (a + b) % _P
    e = (h - (x + y) * (x + y)) % _P
    g = (a - b) % _P
    f = (c + g) % _P
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def usable_point(raw: bytes) -> bool:
    """True when `raw` names a curve point outside the small-order subgroup: under a small-order
    key a forged seal verifies, and OpenSSL does not refuse one. Eight times the point (the
    cofactor) must not be the identity."""
    point = _decoded_point(raw)
    if point is None:
        return False
    for _ in range(3):
        point = _double(point)
    x, y, z, _ = point
    return not (x % _P == 0 and (y - z) % _P == 0)


def fingerprint(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()[:16]


def public_line(raw: bytes) -> str:
    return "ed25519 " + base64.b64encode(raw).decode()


def read_public_keys(path: Path) -> dict[str, Ed25519PublicKey]:
    """Fingerprint -> public key, from the keys file; `keys[N]` names a bad line."""
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        raise Refused("keys", f"cannot read the keys file {path}") from None
    keys: dict[str, Ed25519PublicKey] = {}
    for number, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        raw = _b64(parts[1]) if len(parts) == 2 and parts[0] == "ed25519" else b""
        if len(raw) != 32:
            raise Refused(f"keys[{number}]", "not a line `ed25519 <base64 of 32 bytes>`")
        if not usable_point(raw):
            raise Refused(f"keys[{number}]", "names no curve point or a small-order one")
        try:
            keys[fingerprint(raw)] = Ed25519PublicKey.from_public_bytes(raw)
        except ValueError:
            raise Refused(f"keys[{number}]", "not a usable Ed25519 public key") from None
    return keys


def _raw_public(key: Ed25519PrivateKey | Ed25519PublicKey) -> bytes:
    public = key.public_key() if isinstance(key, Ed25519PrivateKey) else key
    return public.public_bytes(Encoding.Raw, PublicFormat.Raw)


def _private_lines(text: str, source: str) -> list[Ed25519PrivateKey]:
    keys = []
    for number, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        seed = _b64(line)
        if len(seed) != 32:
            raise Refused(f"{source}[{number}]", "a signing key line is base64 of 32 bytes")
        keys.append(Ed25519PrivateKey.from_private_bytes(seed))
    return keys


def read_private_keys(key_files: list[str]) -> list[Ed25519PrivateKey]:
    """Every private key given, the environment's first, each once."""
    keys = _private_lines(os.environ.get(KEYS_ENV, ""), KEYS_ENV)
    for name in key_files:
        try:
            text = Path(name).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            raise Refused("key-file", f"cannot read the signing key file {name}") from None
        keys += _private_lines(text, "key-file")
    unique: dict[bytes, Ed25519PrivateKey] = {}
    for key in keys:
        unique.setdefault(_raw_public(key), key)
    return list(unique.values())


def _known_signers(
    private: list[Ed25519PrivateKey], public: dict[str, Ed25519PublicKey]
) -> list[tuple[str, Ed25519PrivateKey]]:
    signers = []
    for key in private:
        fp = fingerprint(_raw_public(key))
        if fp not in public:
            raise Refused("key", f"the signing key {fp} is not in the keys file")
        signers.append((fp, key))
    return signers


# ---- the index -----------------------------------------------------------------------------------


def message(kind: str, version: str, sha256: str) -> bytes:
    return "".join(f"{part}\n" for part in (SEAL_LABEL, kind, version, sha256)).encode("utf-8")


def _release(value: str) -> tuple[date, int] | None:
    match = _RELEASE.fullmatch(value)
    if not match:
        return None
    try:
        return date.fromisoformat(match.group(1)), int(match.group(2) or 1)
    except ValueError:
        return None


def _b64(text: str) -> bytes:
    """The bytes of strict base64 text, or b"" when it is not."""
    try:
        return base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        return b""


RAW_HOST = "raw.githubusercontent.com"


def _https(url: str) -> bool:
    """True for an https address on GitHub's raw host and nowhere else: the host is compared
    exactly (lower-cased), with no userinfo, no port and a path. Any whitespace or control
    character refuses it first (`urlsplit` would silently drop a tab or a line break)."""
    if not url.isprintable() or any(c.isspace() for c in url):
        return False
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        return False
    return (
        parts.scheme == "https"
        and parts.netloc.lower() == RAW_HOST
        and port is None
        and len(parts.path) > 1
        and parts.path.startswith("/")
    )


def _own_address(
    url: str, own: str | None, kind: str, version: str, any_branch: bool = False
) -> bool:
    """True when no repository is named, or the address is exactly that repository's raw address
    of this entry, `<own><kind>/<kind>-<version>.zip` (the host in any case). The same rule as
    `check_addresses` in base-guard.py (tests/test_catalogue_repo_template.py keeps them equal):
    no `..`, `%`, `?`, `#` or whitespace, nothing before or after. With `any_branch` only the
    branch part is free: the repository and the path stay exact."""
    if own is None:
        return True
    if not url.isprintable() or any(c.isspace() or c in "%?#" for c in url) or "/../" in url:
        return False
    prefix = "https://" + RAW_HOST + "/"
    if url[: len(prefix)].lower() == prefix:
        url = prefix + url[len(prefix) :]
    if any_branch:
        repo = "/".join(own.split("/")[:5]) + "/"
        tail = f"/plugins/{kind}/{kind}-{version}.zip"
        branch = url[len(repo) : -len(tail)]
        return (
            url.startswith(repo)
            and url.endswith(tail)
            and len(url) > len(repo) + len(tail)
            and bool(branch)
            and "/../" not in f"/{branch}/"
        )
    return url == f"{own}{kind}/{kind}-{version}.zip"


def _check_texts(value: object, place: str, limit: int) -> None:
    if not isinstance(value, dict):
        raise Refused(place, "a map of language -> text is expected")
    if "ru" not in value:
        raise Refused(f"{place}.ru", "the `ru` text is required")
    for lang, text in value.items():
        if not _LANGUAGE.fullmatch(lang):
            raise Refused(f"{place}.{lang}", "a language is two lower-case letters")
        if not isinstance(text, str) or not 1 <= len(text) <= limit:
            raise Refused(f"{place}.{lang}", f"a text of 1 to {limit} characters is expected")


def _check_seals(value: object, place: str) -> None:
    if not isinstance(value, list):
        raise Refused(place, "a list of seals is expected")
    seen = set()
    for number, item in enumerate(value):
        here = f"{place}[{number}]"
        if not isinstance(item, dict) or set(item) != {"key", "signature"}:
            raise Refused(here, "a seal is exactly `key` and `signature`")
        key, signature = item["key"], item["signature"]
        if not isinstance(key, str) or not _FINGERPRINT.fullmatch(key):
            raise Refused(here, "`key` is a 16-digit lower-case hex fingerprint")
        if not isinstance(signature, str) or len(_b64(signature)) != 64:
            raise Refused(here, "`signature` is base64 of 64 bytes")
        if key in seen:
            raise Refused(here, "a second seal by the same key")
        seen.add(key)


def sealed(entry: dict) -> bool:
    return entry["archive_sha256"] != ""


def check_entry_fields(
    entry: object,
    position: int,
    allow_unsealed: bool,
    own: str | None = None,
    exempt: dict | None = None,
) -> None:
    place = f"entries[{position}]"
    if not isinstance(entry, dict):
        raise Refused(place, "an entry is an object")
    for name in entry:
        if name not in REQUIRED and name not in OPTIONAL:
            raise Refused(f"{place}.{name}", "a field the format does not have")
    for name in REQUIRED:
        if name not in entry:
            raise Refused(f"{place}.{name}", "a required field is missing")
    kind, version = entry["kind"], entry["version"]
    if not isinstance(kind, str) or not _KIND.fullmatch(kind):
        raise Refused(f"{place}.kind", "a kind is [a-z][a-z0-9_]{1,39}")
    if (
        not isinstance(version, str)
        or not _VERSION.fullmatch(version)
        or "/" in version
        or "\\" in version
        or version.startswith(".")
    ):
        raise Refused(f"{place}.version", "a version is 1-40 printable characters, no / or \\")
    for name, limit in TEXT_LIMITS.items():
        if name in entry:
            _check_texts(entry[name], f"{place}.{name}", limit)
    bounds = []
    for name in ("service_min", "service_max"):
        value = entry.get(name)
        if value is None:
            bounds.append(None)
            continue
        key = _release(value) if isinstance(value, str) else None
        if key is None:
            raise Refused(f"{place}.{name}", "release-YYYY-MM-DD[-N] or null is expected")
        bounds.append(key)
    if bounds[0] and bounds[1] and bounds[0] > bounds[1]:
        raise Refused(f"{place}.service_min", "later than service_max")
    for name in ("needs_key", "paid", "withdrawn"):
        if name in entry and not isinstance(entry[name], bool):
            raise Refused(f"{place}.{name}", "true or false is expected")
    _check_seals(entry["seals"], f"{place}.seals")
    url, sha, seals = entry["archive_url"], entry["archive_sha256"], entry["seals"]
    # An entry sealed before keeps its branch only when its address and hash are what they were.
    free = bool(exempt) and exempt.get((kind, version)) == (url, sha)
    if not isinstance(url, str):
        raise Refused(f"{place}.archive_url", "a text is expected")
    if not isinstance(sha, str):
        raise Refused(f"{place}.archive_sha256", "a text is expected")
    if sha == "" and not seals:
        if url and not _https(url):
            raise Refused(f"{place}.archive_url", "a raw.githubusercontent.com address or empty")
        if url and not _own_address(url, own, kind, version):
            raise Refused(f"{place}.archive_url", "empty or this repository's raw address")
        if not allow_unsealed:
            raise Refused(place, "not sealed")
        return
    if not _SHA256.fullmatch(sha):
        raise Refused(f"{place}.archive_sha256", "64 lower-case hex digits are expected")
    if not seals:
        raise Refused(f"{place}.seals", "a sealed entry carries at least one seal")
    if not _https(url):
        raise Refused(f"{place}.archive_url", "a sealed entry has a raw GitHub address")
    if not _own_address(url, own, kind, version, any_branch=free):
        raise Refused(f"{place}.archive_url", "this repository's raw address on its branch")


def read_index(path: Path) -> dict:
    try:
        top = json.loads(path.read_bytes())
    except (OSError, ValueError, RecursionError):
        raise Refused("index", f"{path} is not readable JSON") from None
    return top


def check_fields(
    top: object, allow_unsealed: bool, own: str | None = None, exempt: dict | None = None
) -> list[dict]:
    """The entries, every field checked strictly, or `Refused` with the first fault."""
    if not isinstance(top, dict):
        raise Refused("index", "the index is an object")
    for name in top:
        if name not in ("format_version", "entries"):
            raise Refused(name, "a field the format does not have")
    version = top.get("format_version")
    if version != FORMAT_VERSION or isinstance(version, bool):
        raise Refused("format_version", f"format version {FORMAT_VERSION} is expected")
    entries = top.get("entries")
    if not isinstance(entries, list):
        raise Refused("entries", "a list is expected")
    first: dict[tuple[str, str], int] = {}
    for position, entry in enumerate(entries):
        check_entry_fields(entry, position, allow_unsealed, own, exempt)
        pair = (entry["kind"], entry["version"])
        if pair in first:
            earlier = f"entries[{first[pair]}]"
            raise Refused(f"entries[{position}]", f"the same kind and version as {earlier}")
        first[pair] = position
    return entries


# ---- archives ------------------------------------------------------------------------------------


def archive_path(root: Path, entry: dict, place: str) -> Path:
    """`<root>/plugins/<kind>/<kind>-<version>.zip`, after the path rule; never a link."""
    kind, version = entry["kind"], entry["version"]
    folder = root / "plugins" / kind
    path = folder / f"{kind}-{version}.zip"
    for step in (root / "plugins", folder, path):
        try:
            mode = os.lstat(step).st_mode
        except OSError:
            raise Refused(f"{place}.archive", f"no file plugins/{kind}/{path.name}") from None
        if stat.S_ISLNK(mode):
            raise Refused(f"{place}.archive", "a symbolic link is not read")
    if path.resolve().parent != folder.resolve() or not path.is_file():
        raise Refused(f"{place}.archive", f"plugins/{kind}/{path.name} is not a plain file")
    return path


def read_archive(path: Path, place: str) -> bytes:
    if path.stat().st_size > ARCHIVE_MAX_BYTES:
        raise Refused(f"{place}.archive", f"over {ARCHIVE_MAX_BYTES} bytes")
    return path.read_bytes()


def _unsafe(place: str, name: str) -> Refused:
    return Refused(f"{place}.archive", f"unsafe member {name!r}")


def _safe_name(info: zipfile.ZipInfo, place: str) -> PurePosixPath:
    """The member's path, or a refusal: the service refuses the same members at install."""
    name = info.filename
    if not name or "\\" in name or "\x00" in name or name.startswith("/") or _DRIVE.match(name):
        raise _unsafe(place, name)
    if any(part in ("", ".", "..") for part in name.rstrip("/").split("/")):
        raise _unsafe(place, name)
    if info.flag_bits & 0x1:  # encrypted
        raise _unsafe(place, name)
    if info.create_system == 3:  # unix: the mode is in the high bits
        kind = stat.S_IFMT(info.external_attr >> 16)
        if kind not in (0, stat.S_IFREG, stat.S_IFDIR):  # a link, a device, a pipe, a socket
            raise _unsafe(place, name)
    return PurePosixPath(name)


def check_members(zf: zipfile.ZipFile, place: str) -> None:
    """Every member as the service checks it: count, safe names, no duplicates, the declared
    unpacked size under the cap, no file that is also another member's folder."""
    infos = zf.infolist()
    if len(infos) > MAX_MEMBERS:
        raise Refused(f"{place}.archive", f"more than {MAX_MEMBERS} members")
    seen: set[PurePosixPath] = set()
    files: set[PurePosixPath] = set()
    total = 0
    for info in infos:
        path = _safe_name(info, place)
        if path in seen:
            raise _unsafe(place, info.filename)
        seen.add(path)
        if not info.is_dir():
            files.add(path)
            total += info.file_size
    if total > UNPACKED_MAX_BYTES:
        raise Refused(f"{place}.archive", f"over {UNPACKED_MAX_BYTES} bytes unpacked")
    for path in sorted(seen):
        if any(parent in files for parent in path.parents):
            raise _unsafe(place, str(path))


def manifest_of(data: bytes, place: str) -> dict:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            check_members(zf, place)
            tops = [i for i in zf.infolist() if i.filename == "manifest.json" and not i.is_dir()]
            if len(tops) != 1:
                raise Refused(f"{place}.archive", "not exactly one manifest.json at the top")
            with zf.open(tops[0]) as f:
                raw = f.read(MANIFEST_MAX_BYTES + 1)
    except (
        zipfile.BadZipFile,
        zipfile.LargeZipFile,
        zlib.error,
        NotImplementedError,
        ValueError,
        OSError,
        EOFError,
    ):
        raise Refused(f"{place}.archive", "not a readable zip") from None
    if len(raw) > MANIFEST_MAX_BYTES:
        raise Refused(f"{place}.archive", "the manifest is too large")
    try:
        manifest = json.loads(raw)
    except (ValueError, RecursionError):
        raise Refused(f"{place}.archive", "the manifest is not readable JSON") from None
    if not isinstance(manifest, dict):
        raise Refused(f"{place}.archive", "the manifest is not an object")
    return manifest


def check_manifest(entry: dict, data: bytes, place: str) -> None:
    manifest = manifest_of(data, place)
    defaults = {"service_min": None, "service_max": None, "needs_key": False, "paid": False}
    for name in MANIFEST_FIELDS:
        theirs = manifest.get(name, defaults.get(name))
        ours = entry.get(name, defaults.get(name))
        if theirs != ours or type(theirs) is not type(ours):
            raise Refused(f"{place}.manifest.{name}", "differs from the archive's manifest")


def check_seals(entry: dict, public: dict[str, Ed25519PublicKey], place: str) -> None:
    data = message(entry["kind"], entry["version"], entry["archive_sha256"])
    for number, seal in enumerate(entry["seals"]):
        key = public.get(seal["key"])
        if key is None:
            raise Refused(f"{place}.seals[{number}]", "by a key that is not in the keys file")
        try:
            key.verify(base64.b64decode(seal["signature"]), data)
        except InvalidSignature:
            raise Refused(f"{place}.seals[{number}]", "does not verify") from None


def check_archive(
    root: Path, entry: dict, public: dict[str, Ed25519PublicKey], position: int
) -> None:
    """The archive against the entry: path, hash, seals, manifest; for an unsealed entry all but
    the hash and the seals."""
    place = f"entries[{position}]"
    data = read_archive(archive_path(root, entry, place), place)
    if sealed(entry):
        if hashlib.sha256(data).hexdigest() != entry["archive_sha256"]:
            raise Refused(f"{place}.archive_sha256", "the archive is not the one sealed")
        check_seals(entry, public, place)
    check_manifest(entry, data, place)


def check_index(
    top: object,
    root: Path,
    public: dict[str, Ed25519PublicKey],
    allow: bool,
    own: str | None = None,
    exempt: dict | None = None,
) -> None:
    entries = check_fields(top, allow, own, exempt)
    for position, entry in enumerate(entries):
        check_archive(root, entry, public, position)


def write_index(path: Path, top: dict) -> None:
    text = json.dumps(top, indent=2, ensure_ascii=False) + "\n"
    fd, temp = tempfile.mkstemp(dir=path.parent, prefix=".index-", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            out.write(text)
        os.chmod(temp, 0o644)
        os.replace(temp, path)
    except BaseException:
        Path(temp).unlink(missing_ok=True)
        raise


def _seal_item(fp: str, key: Ed25519PrivateKey, entry: dict) -> dict:
    signature = key.sign(message(entry["kind"], entry["version"], entry["archive_sha256"]))
    return {"key": fp, "signature": base64.b64encode(signature).decode()}


# ---- commands ------------------------------------------------------------------------------------


def _inside_git(path: Path) -> bool:
    for folder in (path, *path.parents):
        if (folder / ".git").exists():
            return True
    return False


def cmd_new_key(args: argparse.Namespace) -> int:
    path = Path(args.path).expanduser().absolute()
    if os.path.lexists(path):
        raise Refused("path", f"{path} already exists")
    if not path.parent.is_dir():
        raise Refused("path", f"no folder {path.parent}")
    if _inside_git(path.parent.resolve()):
        raise Refused("path", "the key may not be written inside a git working copy")
    key = Ed25519PrivateKey.generate()
    seed = key.private_bytes_raw()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as out:
        out.write(base64.b64encode(seed).decode() + "\n")
    os.chmod(path, 0o600)
    raw = _raw_public(key)
    print(public_line(raw))
    print(f"fingerprint {fingerprint(raw)}")
    return 0


def cmd_seal(args: argparse.Namespace) -> int:
    index, root = Path(args.index), Path(args.root)
    top = read_index(index)
    entries = check_fields(top, allow_unsealed=True)
    waiting = [position for position, entry in enumerate(entries) if not sealed(entry)]
    if not waiting:
        print("nothing to seal")
        return 0
    public = read_public_keys(Path(args.keys))
    signers = _known_signers(read_private_keys(args.key_file), public)
    if not signers:
        raise Refused("key", f"no signing key given ({KEYS_ENV} or --key-file)")
    base = args.url_base.rstrip("/")
    for position in waiting:
        entry, place = entries[position], f"entries[{position}]"
        data = read_archive(archive_path(root, entry, place), place)
        check_manifest(entry, data, place)
        entry["archive_sha256"] = hashlib.sha256(data).hexdigest()
        entry["seals"] = [_seal_item(fp, key, entry) for fp, key in signers]
        if not entry["archive_url"]:
            kind, version = entry["kind"], entry["version"]
            entry["archive_url"] = f"{base}/plugins/{kind}/{kind}-{version}.zip"
    check_index(top, root, public, allow=False)
    write_index(index, top)
    print(f"sealed {len(waiting)} entr{'y' if len(waiting) == 1 else 'ies'}")
    return 0


def cmd_add_seals(args: argparse.Namespace) -> int:
    index, root = Path(args.index), Path(args.root)
    top = read_index(index)
    public = read_public_keys(Path(args.keys))
    signers = _known_signers(read_private_keys(args.key_file), public)
    if not signers:
        raise Refused("key", f"no signing key given ({KEYS_ENV} or --key-file)")
    check_index(top, root, public, allow=True)
    count = 0
    for entry in top["entries"]:
        if not sealed(entry):
            continue
        for fp, key in signers:
            kept = [seal for seal in entry["seals"] if seal["key"] != fp]
            entry["seals"] = [*kept, _seal_item(fp, key, entry)]
        count += 1
    check_index(top, root, public, allow=True)
    write_index(index, top)
    print(f"added seals to {count} entr{'y' if count == 1 else 'ies'}")
    return 0


def cmd_drop_seals(args: argparse.Namespace) -> int:
    fp = args.fingerprint
    if not _FINGERPRINT.fullmatch(fp):
        raise Refused("fingerprint", "16 lower-case hex digits are expected")
    index = Path(args.index)
    top = read_index(index)
    entries = check_fields(top, allow_unsealed=True)
    dropped = 0
    for position, entry in enumerate(entries):
        kept = [seal for seal in entry["seals"] if seal["key"] != fp]
        if len(kept) == len(entry["seals"]):
            continue
        if not kept:
            raise Refused(f"entries[{position}].seals", f"would be left with no seal but {fp}'s")
        entry["seals"] = kept
        dropped += 1
    if not dropped:
        print(f"no seal by {fp}")
        return 0
    write_index(index, top)
    print(f"dropped {fp}'s seal from {dropped} entr{'y' if dropped == 1 else 'ies'}")
    return 0


def sealed_pairs(top: object) -> dict:
    """(kind, version) -> (archive_url, archive_sha256) of every sealed entry of an index; what it
    cannot read is left out."""
    entries = top.get("entries") if isinstance(top, dict) else None
    pairs = {}
    for entry in entries if isinstance(entries, list) else []:
        if isinstance(entry, dict) and entry.get("archive_sha256"):
            kind, version = entry.get("kind"), entry.get("version")
            if isinstance(kind, str) and isinstance(version, str):
                pairs[(kind, version)] = (entry.get("archive_url"), entry["archive_sha256"])
    return pairs


def cmd_check(args: argparse.Namespace) -> int:
    public = read_public_keys(Path(args.keys))
    top = read_index(Path(args.index))
    own = None
    if args.repository or args.branch:
        if not (args.repository and args.branch):
            raise Refused("check", "--repository and --branch go together")
        own = f"https://{RAW_HOST}/{args.repository}/{args.branch}/plugins/"
    exempt = None
    if args.previous:
        if own is None:
            raise Refused("check", "--previous needs --repository and --branch")
        exempt = sealed_pairs(read_index(Path(args.previous)))
    check_index(top, Path(args.root), public, allow=args.allow_unsealed, own=own, exempt=exempt)
    print("ok")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="catalogue-sign.py", description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)

    new_key = sub.add_parser("new-key", help="make a signing key pair")
    new_key.add_argument("path", help="where the private key goes, outside any git working copy")
    new_key.set_defaults(run=cmd_new_key)

    def signing(command: argparse.ArgumentParser) -> None:
        command.add_argument("index")
        command.add_argument("--root", required=True, help="the catalogue repository's folder")
        command.add_argument("--keys", required=True, help="the public keys file")
        command.add_argument("--key-file", action="append", default=[], help="a private key file")

    seal = sub.add_parser("seal", help="seal every unsealed entry")
    signing(seal)
    seal.add_argument("--url-base", required=True, help="the raw address of the branch")
    seal.set_defaults(run=cmd_seal)

    add = sub.add_parser("add-seals", help="add a seal by every key given to every sealed entry")
    signing(add)
    add.set_defaults(run=cmd_add_seals)

    drop = sub.add_parser("drop-seals", help="remove one key's seals")
    drop.add_argument("index")
    drop.add_argument("--fingerprint", required=True)
    drop.set_defaults(run=cmd_drop_seals)

    check = sub.add_parser("check", help="the strict check of the index and the archives")
    check.add_argument("index")
    check.add_argument("--root", required=True)
    check.add_argument("--keys", required=True)
    check.add_argument("--allow-unsealed", action="store_true")
    check.add_argument("--repository", help="<owner>/<repo>: addresses must be its raw address")
    check.add_argument("--branch", help="the branch the raw addresses name")
    check.add_argument(
        "--previous",
        help="the index as it was before this run: an entry sealed there keeps its address",
    )
    check.set_defaults(run=cmd_check)

    args = parser.parse_args(argv)
    try:
        return args.run(args)
    except Refused as exc:
        print(f"refused {exc.place}: {exc.reason}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
