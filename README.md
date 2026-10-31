# News Magnet plugin catalogue

This repository is the open catalogue of source plugins for News Magnet, a self-hosted news
service. A News Magnet server reads `index.json` from here, shows the plugins on its «Плагины» tab
and installs the one its owner picks. Every plugin listed here was reviewed and accepted, and its
archive is sealed with the catalogue's key; a server installs only an archive whose seal it can
verify with a key it trusts.

What is here:

| Path | What it is |
|---|---|
| `index.json` | The list of plugins (format below). |
| `plugins/<kind>/<kind>-<version>.zip` | One archive per plugin version. |
| `keys/catalogue_key.pub` | The public half of the catalogue's signing key (see `keys/README.md`). |
| `tools/catalogue-sign.py` | The signing tool: makes a key, seals, checks. Needs Python 3.9 or later and `cryptography`. |
| `tools/seal-push.sh` | The seal workflow's step: seals and pushes the sealed index back. |
| `tools/base-guard.py` | The pull-request check against the base branch. |
| `tools/requirements.txt` | The signing tool's libraries, pinned by hash, for the workflows that hold or guard the key. |
| `tests/` | The tools' tests and their sample catalogues. |
| `.github/workflows/guard.yml` | The admission check of a pull request, run from the base branch's code. |
| `.github/workflows/check.yml` | The tools' tests on every pull request; the index check on every push to `main`. |
| `.github/workflows/seal.yml` | Sealing, on a merge and by hand. |

## The index

`index.json` is one JSON object:

```json
{
  "format_version": 1,
  "entries": [
    {
      "kind": "earnings_whispers",
      "title": {"ru": "...", "en": "..."},
      "description": {"ru": "...", "en": "..."},
      "notes": {"ru": "...", "en": "..."},
      "version": "1.0.0",
      "service_min": "release-2026-11-02",
      "service_max": null,
      "archive_url": "https://raw.githubusercontent.com/<owner>/news-magnet-plugins/main/plugins/earnings_whispers/earnings_whispers-1.0.0.zip",
      "archive_sha256": "<64 lower-case hex digits>",
      "seals": [{"key": "<16-hex fingerprint>", "signature": "<base64 of 64 bytes>"}],
      "needs_key": true,
      "paid": false,
      "withdrawn": false
    }
  ]
}
```

Every field of an entry:

| Field | Required | What it holds |
|---|---|---|
| `kind` | yes | The plugin's kind: a lower-case letter, then 1 to 39 lower-case letters, digits or `_`. |
| `title` | yes | Language -> name shown on the tab, 1 to 80 characters. `ru` is required; other languages are two lower-case letters and fall back to `ru`. |
| `description` | yes | Language -> one line about the plugin, 1 to 200 characters; same language rule. |
| `notes` | no | Language -> what the user must know before installing (terms of use, limits), 1 to 500 characters; same language rule. Absent means no note. |
| `version` | yes | The plugin's version: 1 to 40 printable characters with no space, no `/`, no `\`, not starting with `.`. |
| `service_min`, `service_max` | no | The oldest and newest News Magnet release the plugin works with, `release-YYYY-MM-DD` or `release-YYYY-MM-DD-N`. Absent or `null` means no bound. `service_min` may not be later than `service_max`. |
| `archive_url` | yes | Where a server fetches the archive: empty in a submission, or the raw address of the file in this repository, `https://raw.githubusercontent.com/<owner>/<repo>/<branch>/plugins/<kind>/<kind>-<version>.zip`. Filled in by the seal step. Any other address is refused: by the guard on a pull request (only this repository's raw address on the branch), by the strict check (`catalogue-sign.py check`, on pushes to `main` and in the sealing step, with the repository and branch given: exactly this entry's `.../plugins/<kind>/<kind>-<version>.zip`, no `..`, `%`, `?`, `#`, whitespace or control character) and by every server, which skips an entry whose address is not on `raw.githubusercontent.com` (archives are downloaded only from GitHub). |
| `archive_sha256` | yes | The SHA-256 of the archive, 64 lower-case hex digits. Filled in by the seal step. |
| `seals` | yes | The seals: each is exactly `key` (the fingerprint of the key that made it) and `signature`. Filled in by the seal step. |
| `needs_key` | yes | `true` when the user must give the plugin a key for the service it calls. |
| `paid` | yes | `true` when the service the plugin calls costs money. |
| `withdrawn` | no | `true` to stop offering this version. Absent means `false`. |

`kind`, `version`, `service_min`, `service_max`, `needs_key` and `paid` must be exactly what the
plugin's own `manifest.json` inside the archive says; the check refuses an entry that differs.

**A seal** is an Ed25519 signature over four lines, each ending in a newline:
`news-magnet-catalogue-seal-v1`, the kind, the version and the archive's SHA-256. So a seal cannot
be moved to another plugin, another version or another archive. The texts, the address and
`withdrawn` are not sealed: the texts are only shown, the address only says where to fetch (the
hash decides), and a withdrawal is only a hint.

**A sealed entry** has the archive's hash, at least one seal and an address on `raw.githubusercontent.com`. **An unsealed
entry** (a submission waiting for its seal) has `archive_sha256` `""`, `seals` `[]` and an
`archive_url` that is `""` or this repository's raw address. Anything in between is broken: the strict
check and the guard refuse it, and a server skips it.

In this catalogue the address is always this repository's own raw address: the guard refuses a pull
request that adds or changes an entry's address to any other host or repository, and refuses a
change of the address of an entry already sealed on the base branch.

**How a server reads the index.** Leniently: it ignores fields it does not know, ignores a seal or a
language it cannot read, and skips (does not list) an entry that is broken, unsealed, listed twice
for the same kind and version, or carries no seal by a key it trusts. One bad entry never hides the
others. Only a `format_version` other than 1, or an index that is not an object with a list of
entries, makes a server refuse the whole index.

**How the catalogue checks the index.** Strictly: an unknown field, a broken entry, a seal by a key
that is not in `keys/catalogue_key.pub` or a seal that does not verify refuses the whole index; the
archive must have the sealed hash and a manifest that agrees with the entry.

**The format rule for later.** An optional entry field may be added inside version 1: older servers
ignore it. Anything an older server must not misread needs `format_version` 2.

## Submitting a plugin

Open a pull request that adds exactly two things:

1. the archive, `plugins/<kind>/<kind>-<version>.zip`: a zip with the plugin's `manifest.json` at
   the top;
2. its entry in `index.json`, unsealed: `archive_sha256` `""`, `seals` `[]`, `archive_url` `""`
   (the seal step fills it in) or this repository's raw address of the file.

Fill in the pull request template: what the plugin does, every address in its manifest, its
libraries, whether it needs a key, its price, a link to the service it calls, any terms of use the
entry's `notes` must state, and the plugin's licence.

The archive must be safe to unpack. The check refuses an archive with an unsafe member name (`..`,
an absolute path, a backslash, a drive letter), a link or device member, an encrypted or repeated
member, a file that is also a folder, more than 500 members, or more than 50 MB unpacked; the
archive itself is at most 5 MB. A News Magnet server refuses the same archives at install, so
nothing is sealed that every server would refuse.

You can run the check yourself before opening the pull request:

```
python3 -m pip install cryptography   # Python 3.9 or later
python3 tools/catalogue-sign.py check index.json --root . --keys keys/catalogue_key.pub --allow-unsealed
```

## Who admits a plugin

The project's agent reviews every submission: what the plugin does, which addresses it reaches and
what it costs. A plugin is merged only after the project owner says yes to that plugin. Nothing
enters the catalogue on the agent's review alone.

The reviewer also opens the pull request's file list on GitHub and checks that no tool, workflow or
guard file changed alongside the plugin. The guard (`guard.yml`) refuses a pull request that mixes a
plugin with any other file, but only a person decides who may merge; the workflows enforce nothing
about that.

Write access to this repository equals access to the signing key: whoever can merge a change to a
workflow or a tool on `main`, or run the seal workflow, can reach the key. Give write access to the
owner alone.

## Sealing

When a submission is merged into `main`, the seal workflow seals it automatically with the
catalogue's key: it fills in the archive's hash and address, adds the seal, runs the strict check
and pushes the sealed `index.json` back to `main`. Until then the entry is unsealed and every server
skips it.

The workflow can also be run by hand (Actions page, "seal", "Run workflow") on `main` or on the
branch `seal-test` only (the job does not start on any other branch), in three modes. The branch
`seal-test` exists only for the sealing test on GitHub; when that test is over it is removed from the
environment's branches and from `seal.yml`:

- `seal`: seal every unsealed entry (the same as after a merge);
- `add-seals`: add a seal by every key the workflow has to every sealed entry (for a key change);
- `drop-seals` with a `fingerprint`: remove that key's seals from every entry (the end of a key
  change).

An archive sealed on another branch gets that branch's raw address. On a branch other than `main`
the sealing step checks that only the entries it sealed in that run carry the branch's address:
entries already sealed keep the address they were sealed with (the guard refuses a changed
address on a sealed entry).

A run that was cancelled (or failed to push) leaves nothing half done: run the workflow again.

The private keys live in the secrets of the GitHub environment `catalogue-signing`, not in the
repository's own secrets. The environment allows only the branches `main` and `seal-test`, and only
the sealing job names it, so no other job and no other branch can read the keys.

## Sealed archives never change

A sealed archive is never replaced: a new version of a plugin is a new file and a new entry. An
entry's service range is bound to the manifest inside its sealed archive, so an existing version
cannot be re-ranged. To stop offering a version, either withdraw it (set `"withdrawn": true` in its
entry, edited on GitHub; the check confirms the file still matches) or publish a new version with
the new range.

The check enforces this on every pull request by comparing it with the base branch
(`tools/base-guard.py`, run by `guard.yml` from the base branch's code, so a pull request cannot
change the guard it is checked by). It refuses:

- a file under `plugins/` that the base branch already has and the pull request changes, deletes or
  renames;
- an entry sealed on the base branch that the pull request removes, resets to unsealed, or points at
  another archive hash or another archive address;
- a path added under `plugins/` that is not `plugins/<kind>/<kind>-<version>.zip` of an entry in the
  pull request's index, or is not a regular file (a link or an executable is refused);
- an archive address, on an entry the pull request adds or changes, that is not empty and is not
  this repository's raw address;
- a file or a link named `plugins` (the folder itself replaced), and a `kind`, `version` or
  `archive_url` that is not a text.

So one kind and version never has two sealed archives.

## Changes that are not plugins

A change to anything that is not a plugin (this README, the tools, the workflows, the keys) is its
own pull request, never mixed with a plugin submission: the check fails a pull request that touches
`plugins/` or `index.json` together with anything else. The tools' tests run on every pull
request, with the pull request's own code and no secrets: they show whether a change to the tools
works, they do not admit anything. The owner reads it in full and merges it himself, because a
change to a workflow or a tool can reach the signing key once it is merged.

## Branch protection

The seal workflow pushes the sealed `index.json` straight to the branch it ran on, as the GitHub
Actions bot. A rule on `main` that requires every change to go through a pull request blocks that
push, so the rule must let the Actions bot push, or not be set. The rule should require the checks
`guard` and `check` to pass before a merge. Whether the required checks also apply to the seal
commit is to be confirmed in the live test of the sealing on GitHub.

## Setting up the repository

Once, on GitHub, before the first plugin is merged:

1. Settings, Environments: `catalogue-signing`. If the environment already exists (a sealing run
   creates it), open it; otherwise create it. Under deployment branches choose selected branches and
   set the branch limit to `main` and `seal-test` (`seal-test` is removed after the sealing test).
2. In that environment add the secret `CATALOGUE_SIGNING_KEY_A` (the private key file's content).
   Do not add the keys as repository secrets.
3. Settings, Branches: protect `main` as in "Branch protection".

## Replacing the key

The owner replaces the catalogue's key himself: a computer with Python and the buttons on GitHub
are enough. The private key exists only in the secrets `CATALOGUE_SIGNING_KEY_A` and
`CATALOGUE_SIGNING_KEY_B` of the environment `catalogue-signing`. At rest one of the two exists; during a key change both exist, the old
key and the new one. Two named slots are used because GitHub never shows a secret's value: the old
key cannot be copied to a new name, so the new key goes into the free slot. The secrets list shows
which slot is taken.

What a server trusts: the key text its owner saved on the «Плагины» tab, or, when nothing is saved
there, the key built into the News Magnet release it runs. **The text saved on the tab replaces the
built-in key; it does not add to it.**

### A planned change

Do these steps in this order. Each step that is a pull request is merged before the next step
starts.

1. On any computer with Python and `cryptography`:
   `python3 tools/catalogue-sign.py new-key <a path outside any repository>`. It writes the new
   private key to that path and prints the new public line and its fingerprint.
2. Open a pull request that adds the new public line to `keys/catalogue_key.pub` and keeps the old
   line; merge it. (Before it is merged, the strict check refuses every seal by the new key.) On
   each server whose «Плагины» tab has saved key text, paste both lines there, the old and the new:
   the saved text replaces the built-in key, so pasting only the new line drops the old key at
   once. A server with nothing saved keeps the built-in key.
3. On GitHub, the catalogue's Settings, Environments, `catalogue-signing`: add the content of the new
   private key file as the free slot (`CATALOGUE_SIGNING_KEY_A` or `CATALOGUE_SIGNING_KEY_B`,
   whichever is not listed). The old slot stays. Then delete the key file from the computer. From
   now on every newly accepted plugin is sealed with both keys, so servers that trust either key
   list it.
4. On the Actions page, run the seal workflow in mode `add-seals`: every existing entry gets a seal
   by the new key beside the old one.
5. Only after step 4 has finished: the next News Magnet release carries the new line alone in its
   built-in key file (an ordinary change of the service). This is safe because every entry now
   carries a seal by the new key.
6. When the servers trust the new key (they run that release, or the new line is on their tab), end
   the change in this order:
   1. delete the old key's secret slot, so nothing new is sealed with it;
   2. run the seal workflow in mode `drop-seals` with the old key's fingerprint;
   3. open a pull request that removes the old line from `keys/catalogue_key.pub`, and merge it
      (doing this before step 6.2 makes the strict check refuse the old seals);
   4. remove the old line from every server's tab.

A server that has saved key text never follows later changes of the built-in key: its owner changes
the tab.

### A leaked key, at once

Do these steps in this order:

1. Delete the leaked key's secret slot first (as in step 6.1), so nothing more is sealed with it.
2. Steps 1 and 2 above: a new key, and its line added to `keys/catalogue_key.pub` (merged). Never
   paste the leaked private key line, or the new one, anywhere: not in an issue, a chat, a commit
   or a pull request.
3. Step 3: the new private key into the free slot.
4. Step 4: `add-seals`.
5. As soon as `add-seals` has finished, without waiting for the release: on every server, paste the
   new line alone on the «Плагины» tab. A server with nothing saved trusts the leaked key until it
   runs the release in step 7, so the tab is the immediate fix.
6. Steps 6.2 and 6.3: `drop-seals` with the leaked key's fingerprint, then remove its line.
7. The next News Magnet release carries the new line alone.

Plugins merged between deleting the leaked slot and adding the new key stay unsealed (servers skip
them) until the new key is in place; then run the seal workflow in mode `seal`.

## Licence

The repository's own files (the tools, the workflows, the texts and the index) are under the MIT
licence, see `LICENSE`. Each plugin archive is under its author's licence, named in the pull request
that added it.
