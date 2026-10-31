#!/usr/bin/env bash
# The seal workflow's step: runs one mode of the signing tool on the branch, then the strict check,
# and pushes the sealed index.json back to that branch as the Actions bot.
#
#   seal-push.sh --branch <name> --mode seal|add-seals|drop-seals [--url-base <raw base>]
#                  [--repository <owner/repo>] [--fingerprint <hex>]
#
# The private keys come only from CATALOGUE_SIGNING_KEYS (the tool reads it); nothing here prints
# them. Nothing changed: exit 0 with no commit. A rejected push (the branch moved meanwhile, for
# example a second merge): fetch, reset to the new head, run the mode and the check again (both
# are deterministic and leave sealed entries alone) and push again; at most three attempts.
set -euo pipefail

branch="" mode="" url_base="" fingerprint="" repository=""
while [ $# -gt 0 ]; do
  case "$1" in
    --branch) branch="$2"; shift 2 ;;
    --mode) mode="$2"; shift 2 ;;
    --url-base) url_base="$2"; shift 2 ;;
    --fingerprint) fingerprint="$2"; shift 2 ;;
    --repository) repository="$2"; shift 2 ;;
    *) echo "seal-push: unknown argument $1" >&2; exit 2 ;;
  esac
done
[ -n "$branch" ] || { echo "seal-push: --branch is required" >&2; exit 2; }

cd "$(dirname "$0")/.."
python="${PYTHON:-python3}"
tool=(tools/catalogue-sign.py)
keys=keys/catalogue_key.pub

run_mode() {
  case "$mode" in
    seal)
      [ -n "$url_base" ] || { echo "seal-push: seal needs --url-base" >&2; return 2; }
      "$python" "${tool[@]}" seal index.json --root . --keys "$keys" --url-base "$url_base" ;;
    add-seals)
      "$python" "${tool[@]}" add-seals index.json --root . --keys "$keys" ;;
    drop-seals)
      [ -n "$fingerprint" ] || { echo "seal-push: drop-seals needs --fingerprint" >&2; return 2; }
      "$python" "${tool[@]}" drop-seals index.json --fingerprint "$fingerprint" ;;
    *)
      echo "seal-push: unknown mode '$mode'" >&2; return 2 ;;
  esac
}

before="$(mktemp)"
trap 'rm -f "$before"' EXIT

for attempt in 1 2 3; do
  cp index.json "$before"
  run_mode
  # Entries sealed before this run keep the address they were sealed with (it may name another
  # branch); only an entry sealed in this run must carry this branch's raw address.
  scope=()
  [ -z "$repository" ] || scope=(--repository "$repository" --branch "$branch" --previous "$before")
  "$python" "${tool[@]}" check index.json --root . --keys "$keys" ${scope[@]+"${scope[@]}"}
  if git diff --quiet -- index.json; then
    echo "nothing to commit on $branch"
    exit 0
  fi
  git add index.json
  bot="github-actions[bot]" mail="41898282+github-actions[bot]@users.noreply.github.com"
  GIT_AUTHOR_NAME="$bot" GIT_AUTHOR_EMAIL="$mail" GIT_COMMITTER_NAME="$bot" GIT_COMMITTER_EMAIL="$mail" \
    git commit -q -m "Seal the catalogue ($mode)"
  if git push -q origin "HEAD:refs/heads/$branch"; then
    echo "pushed to $branch"
    exit 0
  fi
  echo "the push to $branch was rejected (attempt $attempt); starting again from its new head" >&2
  git fetch -q origin "$branch"
  git reset -q --hard FETCH_HEAD
done
echo "seal-push: could not push to $branch after 3 attempts" >&2
exit 1
