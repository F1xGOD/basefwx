#!/usr/bin/env python3
# BaseFWX - Cryptography Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU General Public License v3.0 or later.

"""Run every configured native runtime test and require complete passing evidence."""

from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET


class TestSuiteError(RuntimeError):
    """The configured native suite did not produce complete passing evidence."""


def inventory_names(inventory: dict) -> list[str]:
    tests = inventory["tests"]
    if not isinstance(tests, list) or not tests:
        raise TestSuiteError("no native runtime tests configured")
    names = [test["name"] for test in tests]
    if any(not isinstance(name, str) or not name for name in names):
        raise TestSuiteError("invalid test name in CTest inventory")
    if len(set(names)) != len(names):
        raise TestSuiteError("duplicate test names in CTest inventory")
    for test in tests:
        if any(prop["name"] == "DISABLED" and prop["value"]
               for prop in test.get("properties", [])):
            raise TestSuiteError(f"required test is disabled: {test['name']}")
    return names


def validate_results(report: Path, expected: list[str]) -> None:
    root = ET.parse(report).getroot()
    if root.tag != "testsuite":
        raise TestSuiteError("unexpected CTest JUnit document")
    cases = root.findall("testcase")
    actual = [case.get("name") for case in cases]
    if Counter(actual) != Counter(expected):
        raise TestSuiteError(
            f"CTest results differ from inventory: expected {expected}, got {actual}"
        )
    for case in cases:
        # CTest exits zero for SKIP_RETURN_CODE and disabled tests. Neither
        # establishes that a required security regression executed and passed.
        if (case.get("status") != "run"
                or any(case.find(tag) is not None
                       for tag in ("failure", "error", "skipped"))):
            raise TestSuiteError(f"required test did not pass: {case.get('name')}")


def run_suite(build_dir: Path, output_junit: Path, *, ctest: str = "ctest",
              config: str = "Release", timeout: int = 1200) -> int:
    output_junit = output_junit.resolve()
    output_junit.parent.mkdir(parents=True, exist_ok=True)
    # A failed preflight must not leave an earlier success at this result path.
    output_junit.unlink(missing_ok=True)
    if not build_dir.is_dir():
        raise TestSuiteError(f"build directory is missing: {build_dir}")
    # Runtime tests opt in automatically through add_test(). Only installation
    # and exported-library checks belong to the explicit packaging lane.
    command = [ctest, "--test-dir", str(build_dir.resolve()), "-C", config,
               "-LE", "^basefwx-packaging$"]
    inventory = subprocess.run(
        command + ["--show-only=json-v1"], capture_output=True, text=True,
        check=True, timeout=30,
    )
    expected = inventory_names(json.loads(inventory.stdout))
    with tempfile.TemporaryDirectory(prefix=".cpp-tests-", dir=output_junit.parent) as tmp:
        report = Path(tmp) / "results.xml"
        try:
            completed = subprocess.run(
                command + ["--output-on-failure", "--no-tests=error",
                           "--timeout", str(timeout), "--output-junit", str(report)],
                timeout=timeout,
            )
            if completed.returncode:
                raise TestSuiteError(f"CTest failed with exit code {completed.returncode}")
            validate_results(report, expected)
        finally:
            if report.is_file():
                report.replace(output_junit)
    return len(expected)


def positive_seconds(value: str) -> int:
    seconds = int(value)
    if seconds <= 0:
        raise argparse.ArgumentTypeError("timeout must be positive")
    return seconds


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", required=True, type=Path)
    parser.add_argument("--output-junit", required=True, type=Path)
    parser.add_argument("--ctest", default="ctest")
    parser.add_argument("--config", default="Release")
    parser.add_argument("--timeout", type=positive_seconds, default=1200,
                        help="maximum suite duration in seconds (default: 1200)")
    args = parser.parse_args()
    try:
        count = run_suite(args.build_dir, args.output_junit, ctest=args.ctest,
                          config=args.config, timeout=args.timeout)
    except (TestSuiteError, OSError, ValueError, KeyError, TypeError, ET.ParseError,
            subprocess.SubprocessError) as exc:
        print(f"native runtime tests failed: {exc}", file=sys.stderr)
        return 1
    print(f"PASS: {count} native runtime tests, zero missing or skipped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
