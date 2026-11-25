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
WRAPPER = re.compile(rb"\bredactedError\b")
GO_NON_CODE = re.compile(
    rb"""//[^\n]*|/\*.*?\*/|`[^`]*`|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'""",
    re.DOTALL,
)
WRAPPER_NAME = rb"redactedError(?![A-Za-z_0-9\x80-\xff])"
WRAPPER_TYPE = re.compile(rb"^[ \t]*type[ \t]+" + WRAPPER_NAME)
TYPE_GROUP = re.compile(rb"^[ \t]*type[ \t]*\(")
GROUPED_WRAPPER = re.compile(rb"^[ \t]*" + WRAPPER_NAME + rb"(?=[ \t]*[^ \t);])")
DELIMITER = re.compile(rb"[(){}\[\]]")
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


def declares_wrapper(lines):
    """Find the wrapper's type spec after masking comments and literals."""
    source = b"".join(line for _, line in lines)
    source = GO_NON_CODE.sub(lambda match: re.sub(rb"[^\n]", b" ", match[0]), source)
    depth = 0
    for line in source.splitlines():
        if depth == 0:
            if WRAPPER_TYPE.match(line):
                return True
            group = TYPE_GROUP.match(line)
            if group is None:
                continue
            depth = 1
            line = line[group.end():]
        if depth == 1 and GROUPED_WRAPPER.match(line):
            return True
        depth += sum(1 if token in b"([{" else -1 for token in DELIMITER.findall(line))
    return False


def check_parity():
    """Discover redaction copies in the index and compare their working-tree contents."""
    raw_paths = subprocess.check_output(
        ["git", "ls-files", "-z", "--", ":(glob)**/*.go", ":(exclude,glob)**/*_test.go"],
        timeout=60,
    ).split(b"\0")
    tracked = [Path(os.fsdecode(raw_path)) for raw_path in raw_paths if raw_path]
    for path in EXCEPTIONS:
        if path not in tracked:
            raise ValueError(f"{path}:1: stale exception (path is not tracked)")

    copies = {}
    for path in tracked:
        lines = read_source(path)
        if path in EXCEPTIONS:
            if not declares_wrapper(lines):
                raise ValueError(f"{path}:1: stale exception (missing redactedError declaration)")
        elif any(WRAPPER.search(line) for _, line in lines):
            if path.name != "redact.go":
                raise ValueError(f"{path}:1: redactedError reference outside the parity set")
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
