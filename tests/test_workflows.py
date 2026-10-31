"""The three workflow files, read as text (no YAML library needed), and the guard's scope rule
replayed on lists of changed files."""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
WORKFLOWS = ROOT / ".github" / "workflows"
CHECK = (WORKFLOWS / "check.yml").read_text(encoding="utf-8")
GUARD_YML = (WORKFLOWS / "guard.yml").read_text(encoding="utf-8")
SEAL = (WORKFLOWS / "seal.yml").read_text(encoding="utf-8")
SLOTS = ("CATALOGUE_SIGNING_KEY_A", "CATALOGUE_SIGNING_KEY_B")


def steps(text: str) -> dict[str, str]:
    """Step name -> the step's text; every step starts with `- name:`."""
    found = {}
    parts = re.split(r"^ {6}- name: ", text, flags=re.M)
    for part in parts[1:]:
        name, _, body = part.partition("\n")
        found[name.strip()] = body
    return found


def without_comments(text: str) -> str:
    return "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))


def _guard():
    spec = importlib.util.spec_from_file_location("base_guard", ROOT / "tools" / "base-guard.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


GUARD = _guard()


def test_the_secret_slots_appear_only_in_the_sealing_step():
    seal_steps = steps(SEAL)
    for name, body in seal_steps.items():
        named = [slot for slot in SLOTS if f"secrets.{slot}" in body]
        assert named == (list(SLOTS) if name == "Seal and push" else []), name
    code = without_comments(SEAL) + without_comments(CHECK) + without_comments(GUARD_YML)
    assert code.count("secrets.") == 2
    assert "secrets." not in without_comments(CHECK)
    assert "secrets." not in without_comments(GUARD_YML)


def test_the_signing_secrets_belong_to_an_environment_named_by_the_sealing_job_only():
    assert re.search(r"^    environment: catalogue-signing$", SEAL, re.M)
    for text in (CHECK, GUARD_YML):
        assert "environment:" not in without_comments(text)


def test_the_hand_run_and_the_job_are_limited_to_main():
    assert re.search(r"^    if: github\.ref == 'refs/heads/main'$", SEAL, re.M)


def test_the_seal_checks_out_and_pushes_the_branch_it_ran_on():
    seal_steps = steps(SEAL)
    assert "ref: ${{ github.ref_name }}" in seal_steps["Check out the branch head"]
    sealing = seal_steps["Seal and push"]
    assert "BRANCH: ${{ github.ref_name }}" in sealing
    assert '--branch "$BRANCH"' in sealing
    # `main` is named only as the branch whose pushes start a run and the branch a run may use.
    code = without_comments(SEAL)
    assert "branches: [main]" in code
    assert code.count("refs/heads/main") == 1


def test_the_url_base_is_built_from_the_repository_and_the_branch():
    sealing = steps(SEAL)["Seal and push"]
    base = "https://raw.githubusercontent.com/${{ github.repository }}/${{ github.ref_name }}"
    assert f"URL_BASE: {base}" in sealing
    assert '--url-base "$URL_BASE"' in sealing


def test_inputs_reach_the_script_only_through_the_environment():
    for text in (SEAL, CHECK, GUARD_YML):
        for line in without_comments(text).splitlines():
            if line.strip().startswith("run:"):
                assert "${{" not in line, line


def test_every_action_is_pinned_by_a_full_commit():
    for text in (SEAL, CHECK, GUARD_YML):
        uses = re.findall(r"uses: (\S+)", text)
        assert uses
        for action in uses:
            assert re.fullmatch(r"[\w.-]+/[\w.-]+@[0-9a-f]{40}", action), action


def test_libraries_are_pinned_by_version():
    for text in (CHECK,):
        for line in text.splitlines():
            if "pip install" in line:
                packages = line.split("pip install", 1)[1].split()
                assert packages and all(re.fullmatch(r"[\w-]+==[\w.]+", p) for p in packages)


def test_the_keyed_workflows_install_from_the_hashed_list():
    for text in (SEAL, GUARD_YML):
        installs = [line for line in without_comments(text).splitlines() if "pip install" in line]
        assert installs
        for line in installs:
            assert line.strip().endswith(
                "pip install --require-hashes -r tools/requirements.txt"
            ), line
    pins = (ROOT / "tools" / "requirements.txt").read_text(encoding="utf-8")
    for package in re.findall(r"^([\w-]+)==", pins, re.M):
        assert re.search(
            rf"^{package}==[\w.]+ \\\n(    --hash=sha256:[0-9a-f]{{64}}( \\)?\n?)+", pins, re.M
        )


def test_the_permissions_and_one_seal_run_at_a_time():
    assert re.search(r"^permissions:\n  contents: read$", CHECK, re.M)
    assert re.search(r"^permissions:\n  contents: read$", GUARD_YML, re.M)
    assert re.search(r"^permissions:\n  contents: write$", SEAL, re.M)
    assert re.search(r"^concurrency:\n  group: seal\n  cancel-in-progress: false$", SEAL, re.M)


def test_the_seal_runs_on_a_merge_into_main_and_by_hand_in_three_modes():
    assert re.search(r"paths:\n\s+- index\.json\n\s+- \"plugins/\*\*\"", SEAL)
    assert "workflow_dispatch:" in SEAL
    assert "options: [seal, add-seals, drop-seals]" in SEAL
    assert "MODE: ${{ inputs.mode || 'seal' }}" in steps(SEAL)["Seal and push"]


def test_the_check_runs_on_pull_requests_and_main_pushes_and_trusts_no_pull_request():
    check_steps = steps(CHECK)
    assert re.search(r"^on:\n  pull_request:\n  push:\n    branches: \[main\]$", CHECK, re.M)
    assert "persist-credentials: false" in check_steps["Check out"]
    strict = check_steps["Check the index and the archives"]
    assert "if: github.event_name == 'push'" in strict
    assert "--keys keys/catalogue_key.pub --allow-unsealed" in strict
    assert "base-guard" not in without_comments(CHECK)
    tests = check_steps["Test the tools"]
    assert "if: github.event_name == 'pull_request'" in tests
    assert "pytest" in tests


def test_the_guard_runs_from_the_base_branch_and_reads_the_pull_request_only_as_data():
    code = without_comments(GUARD_YML)
    assert re.search(r"^on:\n  pull_request_target:$", code, re.M)
    assert "pull_request:" not in code
    guard_steps = steps(GUARD_YML)
    checkout = guard_steps["Check out the base branch"]
    # The default ref of this event is the base branch; no step names another one.
    assert "ref:" not in checkout and "repository:" not in checkout
    assert "head.sha" not in code and "head.ref" not in code and "head_ref" not in code
    assert code.count("actions/checkout@") == 1
    fetch = guard_steps["Fetch the pull request as data"]
    assert 'git fetch --no-tags origin "refs/pull/$PR_NUMBER/head"' in fetch
    assert "git merge-tree --write-tree HEAD FETCH_HEAD" in fetch
    assert "git checkout" not in code and "git merge " not in code and "git switch" not in code
    compare = guard_steps["Compare with the base branch"]
    assert 'python tools/base-guard.py --base HEAD --head "$MERGED"' in compare
    strict = guard_steps["Check the index and the archives"]
    assert 'git archive "$MERGED" index.json plugins' in strict
    # The tool and the keys are the workspace's (the base branch); only the data is the PR's.
    assert "python tools/catalogue-sign.py check" in strict
    assert "--keys keys/catalogue_key.pub" in strict
    # No step runs, imports or installs a path from the pull request's folder.
    for name, body in guard_steps.items():
        for line in without_comments(body).splitlines():
            if "RUNNER_TEMP/head" in line:
                assert (
                    ("python tools/catalogue-sign.py check" in line)
                    or "mkdir" in line
                    or "tar -x" in line
                ), line
        assert "pip install" not in body or "tools/requirements.txt" in body, name


@pytest.mark.parametrize(
    ("paths", "scope"),
    [
        (["index.json", "plugins/a_b/a_b-1.0.0.zip"], "plugins"),
        (["index.json"], "plugins"),
        (["README.md", "tools/catalogue-sign.py", ".github/workflows/seal.yml"], "tooling"),
        (["keys/catalogue_key.pub"], "tooling"),
        ([], "tooling"),
        (["index.json", "README.md"], None),
        (["plugins/a_b/a_b-1.0.0.zip", "keys/catalogue_key.pub"], None),
        (["plugins/a_b/a_b-1.0.0.zip", ".github/workflows/check.yml"], None),
    ],
)
def test_the_scope_rule_on_file_lists(paths, scope):
    if scope is None:
        with pytest.raises(GUARD.Refused) as caught:
            GUARD.scope_of(paths)
        assert caught.value.place == "scope"
    else:
        assert GUARD.scope_of(paths) == scope


def test_the_template_files_are_there():
    for name in (
        "README.md",
        "LICENSE",
        "index.json",
        "plugins/.gitkeep",
        "keys/catalogue_key.pub",
        "keys/README.md",
        ".github/PULL_REQUEST_TEMPLATE.md",
        "tools/seal-push.sh",
        "tools/base-guard.py",
        "tools/requirements.txt",
        ".github/workflows/guard.yml",
    ):
        assert (ROOT / name).is_file(), name
    keys = (ROOT / "keys" / "catalogue_key.pub").read_text(encoding="utf-8").splitlines()
    assert all(not line or line.startswith(("#", "ed25519 ")) for line in keys)


def test_the_guard_checkout_keeps_no_credentials_and_pipes_run_under_bash():
    guard_steps = steps(GUARD_YML)
    assert "persist-credentials: false" in guard_steps["Check out the base branch"]
    for name, body in guard_steps.items():
        if re.search(r"^\s+git archive .*\|", body, re.M):
            assert re.search(r"^\s+shell: bash$", body, re.M), name


def test_the_strict_checks_are_given_the_repository_and_the_branch_through_env():
    wanted = {
        GUARD_YML: (
            "Check the index and the archives",
            "github.repository",
            "github.event.pull_request.base.ref",
        ),
        CHECK: ("Check the index and the archives", "github.repository", "github.ref_name"),
        SEAL: ("Seal and push", "github.repository", "github.ref_name"),
    }
    for text, (step, repository, branch) in wanted.items():
        body = steps(text)[step]
        assert f"${{{{ {repository} }}}}" in body and f"${{{{ {branch} }}}}" in body, step
        run = body.split("run:", 1)[1]
        assert "${{" not in run
    guard_run = steps(GUARD_YML)["Check the index and the archives"]
    assert '--repository "$REPOSITORY" --branch' in guard_run
    assert '--repository "$REPOSITORY"' in steps(SEAL)["Seal and push"]
