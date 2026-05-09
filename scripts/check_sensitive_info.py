#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Sequence


@dataclass(frozen=True)
class Match:
    path: str
    line: int
    rule: str
    snippet: str


@dataclass(frozen=True)
class PatternRule:
    name: str
    pattern: re.Pattern[bytes]


HIGH_CONFIDENCE_RULES: Sequence[PatternRule] = (
    PatternRule("Private key block", re.compile(rb"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")),
    PatternRule("GitHub personal access token", re.compile(rb"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b")),
    PatternRule("GitHub fine-grained token", re.compile(rb"\bgithub_pat_[A-Za-z0-9_]{20,}\b")),
    PatternRule("OpenAI-style API key", re.compile(rb"\bsk-[A-Za-z0-9_-]{20,}\b")),
    PatternRule("Anthropic-style API key", re.compile(rb"\bsk-ant-[A-Za-z0-9_-]{20,}\b")),
    PatternRule("AWS access key ID", re.compile(rb"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    PatternRule("Google API key", re.compile(rb"\bAIza[0-9A-Za-z\-_]{35}\b")),
    PatternRule("Slack token", re.compile(rb"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
)

GENERIC_SECRET_LINE = re.compile(
    r"""(?ix)
    \b(
        api[_-]?key |
        access[_-]?token |
        auth[_-]?token |
        refresh[_-]?token |
        secret |
        secret[_-]?key |
        client[_-]?secret |
        password |
        passwd
    )\b
    \s*[:=]\s*
    (?:
        ["']([^"'\n]{8,})["'] |
        ([^\s,#}{]{12,})
    )
    """
)

PLACEHOLDER_MARKERS = (
    "example",
    "placeholder",
    "sample",
    "dummy",
    "test",
    "fake",
    "mock",
    "replace_me",
    "replace-with",
    "changeme",
    "change-me",
    "your_",
    "your-",
    "yourkey",
    "yourtoken",
    "yoursecret",
    "yourpassword",
    "<redacted>",
    "redacted",
    "xxxx",
    "todo",
    "none",
    "null",
)


def git(*args: str, text: bool = False) -> str | bytes:
    completed = subprocess.run(
        ["git", *args],
        check=True,
        capture_output=True,
        text=text,
    )
    return completed.stdout


def staged_paths() -> List[str]:
    raw = git("diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z")
    return [path.decode("utf-8") for path in raw.split(b"\0") if path]


def staged_file_bytes(path: str) -> bytes:
    return git("show", f":{path}")


def is_binary_blob(data: bytes) -> bool:
    if not data:
        return False
    if b"\0" in data:
        return True
    try:
        data.decode("utf-8")
        return False
    except UnicodeDecodeError:
        return True


def line_number_for_offset(data: bytes, offset: int) -> int:
    return data.count(b"\n", 0, offset) + 1


def sanitize_snippet(text: str) -> str:
    text = text.strip()
    if len(text) > 120:
        text = text[:117] + "..."
    return text


def placeholder_value(value: str) -> bool:
    lowered = value.strip().lower()
    if not lowered:
        return True
    if any(marker in lowered for marker in PLACEHOLDER_MARKERS):
        return True
    if lowered in {"true", "false"}:
        return True
    if re.fullmatch(r"[*xX.\-_]{6,}", value.strip()):
        return True
    return False


def scan_full_content(path: str, data: bytes) -> List[Match]:
    matches: List[Match] = []
    for rule in HIGH_CONFIDENCE_RULES:
        for found in rule.pattern.finditer(data):
            line = line_number_for_offset(data, found.start())
            snippet = sanitize_snippet(found.group(0).decode("utf-8", errors="replace"))
            matches.append(Match(path, line, rule.name, snippet))
    return matches


def parse_added_lines(diff_text: str) -> Iterable[tuple[int, str]]:
    current_line = 0
    in_hunk = False
    for raw_line in diff_text.splitlines():
        if raw_line.startswith("@@"):
            header = re.search(r"\+(\d+)", raw_line)
            if not header:
                in_hunk = False
                continue
            current_line = int(header.group(1))
            in_hunk = True
            continue
        if not in_hunk:
            continue
        if raw_line.startswith("+++"):
            continue
        if raw_line.startswith("+"):
            yield current_line, raw_line[1:]
            current_line += 1
            continue
        if raw_line.startswith("-"):
            continue
        if raw_line.startswith("\\"):
            continue
        current_line += 1


def scan_added_lines(path: str) -> List[Match]:
    diff_text = git("diff", "--cached", "--unified=0", "--no-color", "--", path, text=True)
    matches: List[Match] = []
    for line_number, line in parse_added_lines(diff_text):
        found = GENERIC_SECRET_LINE.search(line)
        if not found:
            continue
        value = found.group(2) or found.group(3) or ""
        if placeholder_value(value):
            continue
        matches.append(
            Match(
                path=path,
                line=line_number,
                rule="Possible secret assignment in added line",
                snippet=sanitize_snippet(line),
            )
        )
    return matches


def scan_staged_files() -> List[Match]:
    matches: List[Match] = []
    for path in staged_paths():
        try:
            data = staged_file_bytes(path)
        except subprocess.CalledProcessError:
            continue
        if is_binary_blob(data):
            continue
        matches.extend(scan_full_content(path, data))
        matches.extend(scan_added_lines(path))
    return matches


def scan_worktree_paths(paths: Sequence[str]) -> List[Match]:
    matches: List[Match] = []
    for path in paths:
        file_path = Path(path)
        if not file_path.is_file():
            continue
        data = file_path.read_bytes()
        if is_binary_blob(data):
            continue
        matches.extend(scan_full_content(path, data))
        text = data.decode("utf-8")
        for idx, line in enumerate(text.splitlines(), start=1):
            found = GENERIC_SECRET_LINE.search(line)
            if not found:
                continue
            value = found.group(2) or found.group(3) or ""
            if placeholder_value(value):
                continue
            matches.append(
                Match(
                    path=path,
                    line=idx,
                    rule="Possible secret assignment",
                    snippet=sanitize_snippet(line),
                )
            )
    return matches


def print_matches(matches: Sequence[Match]) -> None:
    print("Sensitive information check failed. Review these matches before committing:\n")
    for match in matches:
        print(f"- {match.path}:{match.line}  {match.rule}")
        print(f"  {match.snippet}")


def dedupe_matches(matches: Sequence[Match]) -> List[Match]:
    unique = {(match.path, match.line, match.rule, match.snippet): match for match in matches}
    return sorted(unique.values(), key=lambda item: (item.path, item.line, item.rule, item.snippet))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Check staged files or explicit paths for common secrets."
    )
    parser.add_argument(
        "--paths",
        nargs="*",
        help="Scan explicit worktree paths instead of staged files.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        matches = scan_worktree_paths(args.paths) if args.paths else scan_staged_files()
    except subprocess.CalledProcessError as exc:
        print(exc.stderr.decode("utf-8", errors="replace") if isinstance(exc.stderr, bytes) else exc.stderr, file=sys.stderr)
        return 2
    matches = dedupe_matches(matches)

    if not matches:
        print("Sensitive information check passed.")
        return 0

    print_matches(matches)
    print("\nUse `git diff --cached` to inspect the staged content.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
