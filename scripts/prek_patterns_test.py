#!/usr/bin/env python3
"""Pin the pygrep patterns in prek.toml against the cases they must and must not catch.

Those hooks gate every commit, and a hook that cannot fire is worse than no hook: it
looks like coverage. Two successive versions of these patterns shipped bypasses that
review found by probing shapes the author had not considered, so every such shape is
recorded below and asserted here.

Run directly, or via the Lint job in CI. Stdlib only, so it needs no toolchain.

Some expectations are assembled from fragments rather than written literally. That keeps
this file from matching the very patterns it tests, which would otherwise force an
exclusion in prek.toml — and an exclusion is exactly where a real violation would hide.
"""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path

# Fragments, so this file is not itself a violation. See the module docstring.
PS_SLEEP = "Start-" + "Sleep"
WIN_HOME = "C:" + "\\Users\\"
NIX_HOME = "/" + "Users/"
# Composed so this fixture is not itself a match for the hook it exercises.
PS_SLEEP = "start-" + "sleep"

CASES: dict[str, tuple[list[str], list[str]]] = {
    # hook id: (must match, must not match)
    "no-sleep-sync": (
        [
            f"    pwsh -c '{PS_SLEEP} 5'",  # the cmdlet is case-insensitive in PowerShell
            "    std::thread::sleep(Duration::from_millis(50));",  # sleep-ok: pattern fixture, not a call
            "    sleep(Duration::from_millis(50));",  # sleep-ok: pattern fixture, not a call
            "    Sleep(50);",  # sleep-ok: pattern fixture, not a call
            "    sleep_ms(50);",  # sleep-ok: pattern fixture, not a call
            "    SleepEx(50, TRUE);",  # sleep-ok: pattern fixture, not a call
            "    thread::park_timeout(Duration::from_secs(1));",  # sleep-ok: pattern fixture, not a call
            "    rx.recv_timeout(Duration::from_secs(5));",  # sleep-ok: pattern fixture, not a call
            "    cv.wait_timeout(guard, Duration::from_secs(5));",  # sleep-ok: pattern fixture, not a call
            "    WaitForSingleObject(h, 5000);",  # sleep-ok: pattern fixture, not a call
            f'    let c = "pwsh -Command \\"{PS_SLEEP} 5\\"";',
            f'    let c = "pwsh -Command \\"{PS_SLEEP} -Milliseconds 200\\"";',
            f'    let c = "pwsh -Command \\"{PS_SLEEP} -Seconds 12000\\"";',
            "        run: sleep 30",  # sleep-ok: pattern fixture, not a call
            "      - run: sleep 5 && ./flaky",  # sleep-ok: pattern fixture, not a call
            f"    // bare marker does not suppress: {PS_SLEEP} 5  sleep-ok:",
        ],
        [
            "    WaitForSingleObject(h, INFINITE);",
            "    let x = asleep_counter();",
            "    // the child is asleep until torn down",
            f'    let c = "{PS_SLEEP} -Seconds 99999"; // sleep-ok: sentinel the test kills',
            "    conpty::close_pty_raw(raw);",
            "    let _ = out_thread.join();",
        ],
    ),
    "no-hardcoded-user-paths": (
        [
            f'    const P: &str = r"{WIN_HOME}alice\\x";',
            f'    const P: &str = r"{WIN_HOME.lower()}alice\\x";',
            f'    const P: &str = "{NIX_HOME}firstname.lastname/private";',
            f'    const P: &str = "{NIX_HOME}bob";',
            f"Clone it to {NIX_HOME}someone/src/thing and run.",
            f"      working-directory: {NIX_HOME}runner/work",
            # prek matches BYTES, where `\\w` is ASCII-only: a Cyrillic home directory slipped
            # past the pattern while a `str`-compiled harness reported it as caught.
            f'    const P: &str = "{NIX_HOME}\u0410\u043d\u043d\u0430/private";',
            f'    const P: &str = r"{WIN_HOME}\u0410\u043d\u043d\u0430\\secrets";',
            # A sanctioned placeholder is the WHOLE segment; these merely start with one.
            f'    const P: &str = "{NIX_HOME}me.smith/private";',
            f'    const P: &str = "{NIX_HOME}meredith/private";',
            f'    const P: &str = r"{WIN_HOME}example2\\x";',
        ],
        [
            f'    const P: &str = r"{WIN_HOME}me\\x";',
            f'    const P: &str = "{NIX_HOME}example/y";',
            f'    const P: &str = r"{WIN_HOME}Public\\Desktop";',
            f'    const P: &str = r"{WIN_HOME}Default\\NTUSER.DAT";',
            f'    const P: &str = r"{WIN_HOME}All Users\\App";',
            f'    const P: &str = "{NIX_HOME}me";',
            f'    const P: &str = \'"{NIX_HOME}me"\';',
            "    let dir = std::env::temp_dir();",
        ],
    ),
    "tests-in-separate-files": (
        [
            "    #[test]",
            "#[test]",
            "    #[skuld::test]",
            "    #[tokio::test]",
        ],
        [
            "#[cfg(test)]",
            '#[path = "agent_tests.rs"]',
            "mod agent_tests;",
            "mod tests {",
            "    pub fn test_helper() {}",
            "    // #[test] in prose",
        ],
    ),
}


# A pattern only ever sees the files its filters let through, so the filters are as
# load-bearing as the regex: widening one silences a hook without touching its pattern.
# Widening `tests-in-separate-files`'s exclude to `\.rs$` silences it entirely; dropping the
# exclude blocks every legitimate `_tests.rs` file. The other two deliberately have NO filters,
# and prek.toml says why in both places.
FILTERS: dict[str, dict[str, object]] = {
    "no-sleep-sync": {"types": None, "exclude": None, "files": None, "types_or": None, "exclude_types": None, "args": None},
    "no-hardcoded-user-paths": {"types": None, "exclude": None, "files": None, "types_or": None, "exclude_types": None, "args": None},
    "tests-in-separate-files": {
        "types": ["rust"],
        "exclude": r"^tests/|_tests\.rs$",
        "files": None,
        "types_or": None,
        "exclude_types": None,
        "args": None,
    },
}

# Proves the `exclude` filter actually does its job against real paths, not just that its
# string matches what we expect: a filter can be widened (or narrowed) to something that still
# equality-checks correctly against a typo'd expectation. `excluded` paths must be SKIPPED by
# the filter (so a `#[test]` there never reaches the pattern); `scanned` paths must NOT be, so a
# `#[test]` in an implementation file is still caught.
EXCLUDE_PATH_CASES: dict[str, tuple[list[str], list[str]]] = {
    "tests-in-separate-files": (
        [
            "src/shim_tests.rs",
            "src/shim_pty_tests.rs",
            "tests/fail_open_windows.rs",
            "tests/verify_probe_upstream.rs",
            "tests/interactive_fail_open_containment.rs",
        ],
        [
            "src/shim.rs",
            "src/shim_pty.rs",
            "src/main.rs",
            "src/provision.rs",
            # Pins the `^` anchor specifically: unanchored `tests/` (dropping the `^` from
            # `^tests/|_tests\.rs$`) would also skip a `tests/` directory NESTED under `src/` —
            # reopening the inline-`#[test]`-inside-`src/` hole this hook exists to close, while
            # the FILTERS string-equality check alone could not tell an anchored pattern from an
            # unanchored one if both were edited to match.
            "src/tests/helper.rs",
        ],
    ),
}


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    config = tomllib.loads((root / "prek.toml").read_text(encoding="utf-8"))
    hooks = {h["id"]: h for repo in config["repos"] for h in repo["hooks"]}

    failures: list[str] = []
    for hook_id, (must, must_not) in CASES.items():
        if hook_id not in hooks:
            failures.append(f"{hook_id}: no such hook in prek.toml")
            continue
        # An emptied list would otherwise pass in silence, which is the failure this file exists
        # to prevent: a check that reports success while testing nothing.
        if not must:
            failures.append(f"{hook_id}: no positive cases — the pattern is unpinned")
        if not must_not:
            failures.append(f"{hook_id}: no negative cases — nothing stops it matching everything")
        # Compiled and searched as BYTES, because that is what prek does: as a `str`
        # pattern `\w` is Unicode and matches `Анна`, so the harness certified a hook
        # that could not fire on a non-ASCII home path.
        pattern = re.compile(hooks[hook_id]["entry"].encode())
        for line in must:
            if not pattern.search(line.encode() + b"\n"):
                failures.append(f"{hook_id}: should have matched but did not:\n    {line}")
        for line in must_not:
            if pattern.search(line.encode() + b"\n"):
                failures.append(f"{hook_id}: should NOT have matched but did:\n    {line}")

    for hook_id, expected in FILTERS.items():
        hook = hooks.get(hook_id)
        if hook is None:
            continue  # already reported above
        # Every filter key, not just the ones named: an unpinned `files` or `exclude_types`
        # narrows what the hook sees exactly as `exclude` does.
        for key in ("types", "exclude", "files", "types_or", "exclude_types", "args"):
            want = expected.get(key)
            got = hook.get(key)
            if got != want:
                failures.append(
                    f"{hook_id}: {key} is {got!r}, expected {want!r} — "
                    f"a filter change can make the hook inert without touching its pattern"
                )

    for hook_id, (excluded, scanned) in EXCLUDE_PATH_CASES.items():
        hook = hooks.get(hook_id)
        if hook is None:
            continue  # already reported above
        # Same emptiness guard as the `CASES` loop above, and for the same reason: an emptied
        # list here would pass in silence — exactly the "reports success while testing nothing"
        # failure this file's docstring calls out.
        if not excluded:
            failures.append(f"{hook_id}: no excluded-path cases — the exclude filter is unpinned")
        if not scanned:
            failures.append(f"{hook_id}: no scanned-path cases — nothing stops exclude matching everything")
        # `.get`, not a subscript: a hook can appear in EXCLUDE_PATH_CASES while its `exclude` was
        # removed from prek.toml (one of the two mutations this block exists to catch — see the
        # comment on that hook's `exclude` key). A subscript there raises `KeyError` and aborts
        # the whole script before `failures` is ever printed, hiding every other collected result
        # along with it.
        exclude_src = hook.get("exclude")
        if not exclude_src:
            failures.append(f"{hook_id}: has EXCLUDE_PATH_CASES cases but no `exclude` filter in prek.toml")
            continue
        # Bytes, like the `CASES` loop above and for the same reason: prek matches filenames as
        # bytes too, and a `str`-compiled pattern here would certify an `exclude` that a non-ASCII
        # path could silently slip past in real prek even while this check reports it as caught.
        exclude_pattern = re.compile(exclude_src.encode())
        for path in excluded:
            if not exclude_pattern.search(path.encode()):
                failures.append(f"{hook_id}: exclude should skip {path!r} but the pattern does not match it")
        for path in scanned:
            if exclude_pattern.search(path.encode()):
                failures.append(f"{hook_id}: exclude should NOT skip {path!r} but the pattern matches it")

    untested = set(hooks) - set(CASES) - {"cargo-fmt", "cargo-clippy"}
    for hook_id in sorted(untested):
        failures.append(f"{hook_id}: pygrep hook has no cases in this file")
    unfiltered = set(hooks) - set(FILTERS) - {"cargo-fmt", "cargo-clippy"}
    for hook_id in sorted(unfiltered):
        failures.append(f"{hook_id}: pygrep hook has no filter expectations in this file")
    # Mirrors `unfiltered` above: any hook that declares an `exclude` at all should have its own
    # path-level proof the filter does its job, not just a string equality check that could
    # itself be typo'd to something inert (see `EXCLUDE_PATH_CASES`'s own docstring).
    excludes_untested = {hid for hid, h in hooks.items() if h.get("exclude")} - set(EXCLUDE_PATH_CASES)
    for hook_id in sorted(excludes_untested):
        failures.append(f"{hook_id}: hook has an `exclude` filter but no EXCLUDE_PATH_CASES entry")

    if failures:
        print("prek pattern check FAILED:\n", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        return 1

    total = sum(len(m) + len(n) for m, n in CASES.values())
    exclude_total = sum(len(e) + len(s) for e, s in EXCLUDE_PATH_CASES.values())
    print(
        f"prek pattern check passed: {len(CASES)} patterns, {total} cases, {len(FILTERS)} filter sets, "
        f"{len(EXCLUDE_PATH_CASES)} exclude filters, {exclude_total} exclude-path cases"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
