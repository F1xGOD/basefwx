#!/usr/bin/env python3
# BaseFWX - Cryptography Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU General Public License v3.0 or later.

"""Driver regressions using real CTest and isolated setup failure injection."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from run_cpp_tests import TestSuiteError, inventory_names, validate_results


ROOT = Path(__file__).resolve().parents[1]


class NativeDriverTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="basefwx-ctest-driver-")
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name)
        self.report = self.directory / "report.xml"

    def run_ctest_fixture(self, registrations: str) -> subprocess.CompletedProcess[str]:
        self.assertIsNotNone(shutil.which("ctest"), "CTest is required for this test")
        (self.directory / "CTestTestfile.cmake").write_text(registrations)
        return subprocess.run(
            [sys.executable, str(ROOT / "scripts/run_cpp_tests.py"),
             "--build-dir", str(self.directory), "--output-junit", str(self.report)],
            capture_output=True, text=True, timeout=20,
        )

    @staticmethod
    def registration(name: str, exit_code: int = 0) -> str:
        executable = sys.executable.replace("\\", "/").replace('"', '\\"')
        return f'add_test({name} "{executable}" "-c" "raise SystemExit({exit_code})")\n'

    def test_new_runtime_tests_run_without_a_name_allowlist(self) -> None:
        result = self.run_ctest_fixture(
            self.registration("policy_test")
            + self.registration("new_security_regression")
            + self.registration("installation_probe", 1)
            + 'set_tests_properties(installation_probe PROPERTIES LABELS "basefwx-packaging")\n'
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        validate_results(self.report, ["policy_test", "new_security_regression"])

    def test_failed_test_fails_driver(self) -> None:
        result = self.run_ctest_fixture(self.registration("failure", 1))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("CTest failed", result.stderr)
        self.assertTrue(self.report.is_file())

    def test_skipped_test_fails_even_when_ctest_exits_zero(self) -> None:
        result = self.run_ctest_fixture(
            self.registration("skipped", 77)
            + 'set_tests_properties(skipped PROPERTIES SKIP_RETURN_CODE 77)\n'
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("required test did not pass: skipped", result.stderr)

    def test_disabled_test_fails_preflight(self) -> None:
        result = self.run_ctest_fixture(
            self.registration("disabled")
            + 'set_tests_properties(disabled PROPERTIES DISABLED TRUE)\n'
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("required test is disabled", result.stderr)

    def test_missing_executable_fails(self) -> None:
        result = self.run_ctest_fixture('add_test(missing "/nonexistent/basefwx-test")\n')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("CTest failed", result.stderr)

    def test_empty_inventory_fails_and_removes_stale_report(self) -> None:
        self.report.write_text('<testsuite><testcase name="old" status="run"/></testsuite>')
        result = self.run_ctest_fixture("")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no native runtime tests configured", result.stderr)
        self.assertFalse(self.report.exists())

    def test_missing_duplicate_and_unexpected_results_fail(self) -> None:
        for names in (["one"], ["one", "one"], ["one", "two", "extra"]):
            with self.subTest(names=names):
                self.report.write_text(
                    "<testsuite>"
                    + "".join(f'<testcase name="{name}" status="run"/>' for name in names)
                    + "</testsuite>"
                )
                with self.assertRaisesRegex(TestSuiteError, "results differ from inventory"):
                    validate_results(self.report, ["one", "two"])

    def test_missing_report_fails(self) -> None:
        with self.assertRaises(FileNotFoundError):
            validate_results(self.report, ["one"])

    def test_duplicate_inventory_fails(self) -> None:
        with self.assertRaisesRegex(TestSuiteError, "duplicate test names"):
            inventory_names({"tests": [{"name": "one"}, {"name": "one"}]})

    def test_failed_configure_or_build_never_reuses_stale_binary(self) -> None:
        source = (ROOT / "scripts/test_all.sh").read_text()
        # Load this function alone: the surrounding driver installs dependencies
        # and runs large fixtures. Its command wrapper is the injected failure.
        function = source.split("ensure_cpp() {", 1)[1].split("\nensure_java() {", 1)[0]
        script = "ensure_cpp() {" + function + """
ROOT="$1"
CPP_BIN="$2"
TEST_MODE=default
BENCH_ONLY=0
FBENCH=0
RETIRED_MEDIA_ENABLED=0
CPP_REQUIRE_ARGON2=ON
CPP_REQUIRE_OQS=OFF
CPP_REQUIRE_LZMA=OFF
CPP_AVAILABLE=1
FAILURES=()
CALLS=()
log() { :; }
cpp_has_file_cli() { return 0; }
time_cmd_no_fail() {
    CALLS+=("$1")
    [[ "$1" != "$FAIL_STAGE" ]]
}
if ensure_cpp; then
    exit 41
fi
[[ "$CPP_AVAILABLE" == 0 ]] || exit 42
[[ "${FAILURES[*]}" == "$FAIL_STAGE (failed)" ]] || exit 43
if [[ "$FAIL_STAGE" == cpp_configure ]]; then
    [[ "${CALLS[*]}" == cpp_configure ]] || exit 44
else
    [[ "${CALLS[*]}" == 'cpp_configure cpp_build' ]] || exit 45
fi
"""
        for stage in ("cpp_configure", "cpp_build"):
            with self.subTest(stage=stage):
                result = subprocess.run(
                    ["bash", "-u", "-c", script, "test", str(self.directory), sys.executable],
                    env={**os.environ, "FAIL_STAGE": stage},
                    capture_output=True, text=True, timeout=5,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def python_setup_probe(self, *, use_venv: bool, existing_venv: bool,
                           fail_stage: str, missing_requested_python: bool = False,
                           retired: bool = False) -> subprocess.CompletedProcess[str]:
        source = (ROOT / "scripts/test_all.sh").read_text()
        function = source.split("ensure_venv() {", 1)[1].split("\nadd_verify() {", 1)[0]
        main_gate = source.split("\nif ! ensure_venv; then", 1)[1].split(
            '\nphase "PHASE1.1:', 1
        )[0]
        environment = Path(tempfile.mkdtemp(dir=self.directory))
        interpreter = environment / "python"
        if existing_venv:
            interpreter.symlink_to(sys.executable)
        sentinel = environment / "existing-install"
        sentinel.write_bytes(b"existing installed environment must survive")
        script = "ensure_venv() {" + function + """
PY_ROOT="$1"
VENV_DIR="$2"
VENV_PY="$VENV_DIR/python"
FAILURES=()
CALLS=()
LAST_ARGS=()
time_cmd_no_fail() {
    CALLS+=("$1")
    LAST_ARGS=("$@")
    [[ "$1" != "$FAIL_STAGE" ]]
}
trap 'printf "CALLS=%s\\n" "${CALLS[*]}"; printf "ARGS=%s\\n" "${LAST_ARGS[*]}"' EXIT
""" + "\nif ! ensure_venv; then" + main_gate + '\nprintf "SETUP_FINISHED\\n"\n'
        result = subprocess.run(
            ["bash", "-u", "-c", script, "test", str(ROOT / "python"), str(environment)],
            env={**os.environ, "FAIL_STAGE": fail_stage,
                 "USE_VENV": "1" if use_venv else "0",
                 "PYTHON_BIN": "/nonexistent/requested-python" if missing_requested_python else sys.executable,
                 "RETIRED_MEDIA_ENABLED": "1" if retired else "0"},
            capture_output=True, text=True, timeout=5,
        )
        self.assertEqual(sentinel.read_bytes(), b"existing installed environment must survive")
        self.assertEqual(interpreter.is_symlink(), existing_venv)
        return result

    def test_python_setup_stops_at_each_failed_stage(self) -> None:
        cases = [
            (True, False, "venv_create", "venv_create (failed)", "venv_create"),
            (True, False, "none", "venv_create (interpreter missing)", "venv_create"),
            (True, True, "venv_pip", "venv_pip (failed)", "venv_pip"),
            (True, True, "venv_install", "venv_install (failed)", "venv_pip venv_install"),
            (False, False, "venv_pip", "venv_pip (failed)", "venv_pip"),
            (False, False, "venv_install", "venv_install (failed)", "venv_pip venv_install"),
        ]
        for use_venv, existing, stage, message, calls in cases:
            with self.subTest(use_venv=use_venv, existing=existing, stage=stage):
                result = self.python_setup_probe(
                    use_venv=use_venv, existing_venv=existing, fail_stage=stage,
                )
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn(message, result.stdout)
                self.assertIn(f"CALLS={calls}\n", result.stdout)
                self.assertNotIn("SETUP_FINISHED", result.stdout)

    def test_missing_requested_python_does_not_fall_back(self) -> None:
        result = self.python_setup_probe(
            use_venv=False, existing_venv=False, fail_stage="none", missing_requested_python=True,
        )
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("python_unavailable (requested interpreter missing)", result.stdout)
        self.assertIn("CALLS=\n", result.stdout)
        self.assertNotIn("SETUP_FINISHED", result.stdout)

    def test_python_setup_success_keeps_profile_and_installs_current_source(self) -> None:
        for use_venv in (False, True):
            for retired in (False, True):
                with self.subTest(use_venv=use_venv, retired=retired):
                    result = self.python_setup_probe(
                        use_venv=use_venv, existing_venv=use_venv, fail_stage="none", retired=retired,
                    )
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertIn("SETUP_FINISHED", result.stdout)
                    self.assertIn("CALLS=venv_pip venv_install\n", result.stdout)
                    extras = "argon2,retired-media" if retired else "argon2"
                    self.assertIn(f"-m pip install -e {ROOT / 'python'}[{extras}]\n", result.stdout)


if __name__ == "__main__":
    unittest.main()
