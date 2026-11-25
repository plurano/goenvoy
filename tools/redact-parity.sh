#!/usr/bin/env bash
# Compare tracked copies of the opaque error redaction code and its traversal tests.
set -euo pipefail

python3 - <<'PY'
import os
import re
import subprocess
import sys
from itertools import zip_longest
from pathlib import Path


PACKAGE = re.compile(rb"^[ \t]*package[ \t]+")
WRAPPER = re.compile(rb"^[ \t]*type[ \t]+redactedError[ \t]+struct\b")
PERCENT_SPAN = re.compile(rb"^func \(c \*Client\) percentSpan\(")
SCRUB_TEXT = re.compile(rb"^func \(c \*Client\) scrubText\(")


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


def is_shared_copy(lines):
    """Identify the shared wrapper and exclude the separate percentSpan implementation."""
    if not any(WRAPPER.match(line) for _, line in lines):
        return False
    # Why: the standalone percentSpan implementation also names its wrapper redactedError.
    return not any(PERCENT_SPAN.match(line) for _, line in lines) or any(
        SCRUB_TEXT.match(line) for _, line in lines
    )


def check_parity():
    """Discover redaction copies in the index and compare their working-tree contents."""
    tracked = subprocess.check_output(
        ["git", "ls-files", "-z", "--", ":(glob)**/redact.go"], timeout=60
    ).split(b"\0")
    copies = {}
    for raw_path in filter(None, tracked):
        path = Path(os.fsdecode(raw_path))
        lines = read_source(path)
        if is_shared_copy(lines):
            copies[path.parent] = lines
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
