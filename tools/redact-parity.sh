#!/usr/bin/env bash
# Compare tracked copies of the opaque error redaction code and its traversal tests.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
python3 - "$HERE/go" <<'PY'
import os
import re
import subprocess
import sys
from itertools import zip_longest
from pathlib import Path


PACKAGE = re.compile(rb"^[ \t]*package[ \t]+")
WRAPPER = re.compile(rb"\bredactedError\b")
EXCEPTIONS = {
    Path("downloadclient/sabnzbd/redact.go"): "Separate legacy redaction implementation.",
}


def read_source(path):
    """Read physical lines as bytes, including their line endings."""
    try:
        with path.open("rb") as source:
            return list(enumerate(source, 1))
    except FileNotFoundError as error:
        raise ValueError(f"{path}:1: missing file") from error


def without_package(path, lines):
    """Drop the package clause and preserve the original line numbers."""
    index = next((i for i, (_, line) in enumerate(lines) if PACKAGE.match(line)), None)
    if index is None:
        raise ValueError(f"{path}:1: missing package clause")
    return lines[:index] + lines[index + 1:]


def compare(reference, baseline, candidate):
    """Report the first byte difference by its physical line in the candidate."""
    lines = read_source(candidate)
    contents = without_package(candidate, lines)
    for (_, expected), (number, actual) in zip_longest(baseline, contents, fillvalue=(None, None)):
        if expected != actual:
            number = number if number is not None else len(lines) + 1
            raise ValueError(f"{candidate}:{number}: differs from {reference}")


def check_exceptions(tracked):
    """Verify that each exception is tracked and declares the wrapper."""
    for path in EXCEPTIONS:
        if path not in tracked:
            raise ValueError(f"{path}:1: stale exception (path is not tracked)")
        read_source(path)
    result = subprocess.run(
        ["go", "-C", sys.argv[1], "run", "-p", "4", "./redactdecl", "redactedError",
         *(str(path.absolute()) for path in EXCEPTIONS)],
        capture_output=True, text=True, timeout=60, check=False,
    )
    if result.returncode != 0:
        raise ValueError(result.stderr.strip() or f"redactdecl exited {result.returncode}")
    for path, declares in zip(EXCEPTIONS, result.stdout.splitlines(), strict=True):
        if declares != "true":
            raise ValueError(f"{path}:1: stale exception (missing redactedError declaration)")


def check_parity():
    """Discover redaction copies in the index and compare their working-tree contents."""
    raw_paths = subprocess.check_output(
        ["git", "ls-files", "-z", "--", ":(glob)**/*.go"],
        timeout=60,
    ).split(b"\0")
    tracked = [Path(os.fsdecode(raw_path)) for raw_path in raw_paths if raw_path]
    check_exceptions(tracked)

    copies = {}
    for path in tracked:
        if path in EXCEPTIONS or path.name.endswith("_test.go"):
            continue
        lines = read_source(path)
        if path.name == "redact.go":
            copies[path.parent] = lines
        elif any(WRAPPER.search(line) for _, line in lines):
            raise ValueError(f"{path}:1: redactedError reference outside the parity set")
    for directory in copies:
        test_path = directory / "redact_as_internal_test.go"
        if test_path not in tracked:
            raise ValueError(f"{test_path}:1: missing file in git index (untracked or missing parity test)")
    if len(copies) < 2:
        raise ValueError(f"found {len(copies)} redaction copies; need at least 2")

    first, *siblings = copies
    for filename in ("redact.go", "redact_as_internal_test.go"):
        reference = first / filename
        lines = copies[first] if filename == "redact.go" else read_source(reference)
        baseline = without_package(reference, lines)
        for directory in siblings:
            compare(reference, baseline, directory / filename)
    print(f"redact-parity: {len(copies)} redaction copies match")


try:
    check_parity()
except (OSError, ValueError, subprocess.SubprocessError) as error:
    print(f"redact-parity: {error}", file=sys.stderr)
    sys.exit(1)
PY
