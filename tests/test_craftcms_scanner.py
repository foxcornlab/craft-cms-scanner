#!/usr/bin/env python3
"""Tests for craftcms_scanner. Run: python3 -m unittest discover -s tests -v"""

import json
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from craftcms_scanner import (
    CVES,
    FIXED,
    detect_local,
    format_version,
    grade,
    grade_cve,
    parse_version,
    read_version_file,
)


class TestParsing(unittest.TestCase):
    def test_parse(self):
        self.assertEqual(parse_version("5.11.1"), (5, 11, 1))
        self.assertEqual(parse_version("4.18.9"), (4, 18, 9))
        self.assertEqual(parse_version("v5.11.2"), (5, 11, 2))
        self.assertEqual(parse_version("  4.18.8  "), (4, 18, 8))

    def test_parse_accepts_fourth_segment(self):
        self.assertEqual(parse_version("5.11.2.1"), (5, 11, 2))

    def test_parse_rejects_bare_version(self):
        # The incomplete-version trap: no patch number, no grade.
        self.assertIsNone(parse_version("5.11"))
        self.assertIsNone(parse_version("4.18"))
        self.assertIsNone(parse_version("5"))

    def test_parse_rejects_junk(self):
        self.assertIsNone(parse_version("latest"))
        self.assertIsNone(parse_version("5.11.x"))
        self.assertIsNone(parse_version(""))
        self.assertIsNone(parse_version(None))
        self.assertIsNone(parse_version("craftcms/cms 5.11.1"))


class TestHeadlineBoundaries(unittest.TestCase):
    def test_5_11_1_vulnerable_to_all_four(self):
        result = grade("5.11.1")
        self.assertEqual(result["grade"], "VULNERABLE")
        self.assertEqual(result["per_cve"]["CVE-2026-123488"], "VULNERABLE")
        self.assertEqual(result["per_cve"]["CVE-2026-123489"], "VULNERABLE")
        self.assertEqual(result["per_cve"]["CVE-2026-123490"], "VULNERABLE")
        self.assertEqual(result["per_cve"]["CVE-2026-123491"], "VULNERABLE")
        self.assertEqual(result["fixed"], "5.11.2")

    def test_5_11_2_patched(self):
        result = grade("5.11.2")
        self.assertEqual(result["grade"], "PATCHED")
        for cve_id in CVES:
            self.assertEqual(result["per_cve"][cve_id], "PATCHED")

    def test_5_11_3_patched(self):
        self.assertEqual(grade("5.11.3")["grade"], "PATCHED")

    def test_4_18_8_vulnerable(self):
        result = grade("4.18.8")
        self.assertEqual(result["grade"], "VULNERABLE")
        self.assertEqual(result["per_cve"]["CVE-2026-123488"], "VULNERABLE")
        # CVE-2026-123490 never affected Craft 4.
        self.assertEqual(result["per_cve"]["CVE-2026-123490"], "NOT-AFFECTED")

    def test_4_18_9_patched_with_eol_note(self):
        result = grade("4.18.9")
        self.assertEqual(result["grade"], "PATCHED")
        self.assertEqual(result["per_cve"]["CVE-2026-123488"], "PATCHED")
        self.assertEqual(result["per_cve"]["CVE-2026-123490"], "NOT-AFFECTED")
        self.assertIn("end of security support", result["note"])

    def test_4_0_0_vulnerable(self):
        result = grade("4.0.0")
        self.assertEqual(result["grade"], "VULNERABLE")
        self.assertEqual(result["per_cve"]["CVE-2026-123488"], "VULNERABLE")


class TestGetOwnersScopeTrap(unittest.TestCase):
    def test_5_8_16_not_affected_by_123490_but_vulnerable_to_rest(self):
        # The scope trap: 5.8.17 is the floor for CVE-2026-123490. A
        # 5.8.16 install is NOT-AFFECTED for that CVE, but still open
        # to the other three, so the overall grade stays VULNERABLE.
        result = grade("5.8.16")
        self.assertEqual(result["grade"], "VULNERABLE")
        self.assertEqual(result["per_cve"]["CVE-2026-123490"], "NOT-AFFECTED")
        self.assertEqual(result["per_cve"]["CVE-2026-123488"], "VULNERABLE")
        self.assertEqual(result["per_cve"]["CVE-2026-123491"], "VULNERABLE")

    def test_5_8_17_vulnerable_to_123490(self):
        result = grade("5.8.17")
        self.assertEqual(result["per_cve"]["CVE-2026-123490"], "VULNERABLE")

    def test_5_0_0_not_affected_by_123490(self):
        result = grade("5.0.0")
        self.assertEqual(result["per_cve"]["CVE-2026-123490"], "NOT-AFFECTED")
        self.assertEqual(result["grade"], "VULNERABLE")

    def test_grade_cve_direct(self):
        self.assertEqual(grade_cve("CVE-2026-123490", (5, 8, 16)), "NOT-AFFECTED")
        self.assertEqual(grade_cve("CVE-2026-123490", (5, 8, 17)), "VULNERABLE")
        self.assertEqual(grade_cve("CVE-2026-123490", (5, 11, 2)), "PATCHED")
        self.assertEqual(grade_cve("CVE-2026-123490", (4, 18, 8)), "NOT-AFFECTED")


class TestUnknownGrades(unittest.TestCase):
    def test_craft3_unknown(self):
        # Outside the advisory table: EOL, no published mapping, not clean.
        result = grade("3.9.0")
        self.assertEqual(result["grade"], "UNKNOWN")
        self.assertIn("outside the advisory table", result["note"])

    def test_future_branch_unknown(self):
        self.assertEqual(grade("6.0.0")["grade"], "UNKNOWN")

    def test_bare_version_unknown(self):
        result = grade("5.11")
        self.assertEqual(result["grade"], "UNKNOWN")
        self.assertIn("no patch number", result["note"])

    def test_junk_unknown(self):
        self.assertEqual(grade("latest")["grade"], "UNKNOWN")


class TestLocalDetection(unittest.TestCase):
    def _write_lock(self, directory, packages):
        lock = {"packages": packages, "packages-dev": []}
        with open(os.path.join(directory, "composer.lock"), "w") as f:
            json.dump(lock, f)

    def test_detect_from_composer_lock(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._write_lock(tmp, [
                {"name": "psr/log", "version": "3.0.0"},
                {"name": "craftcms/cms", "version": "v5.11.1"},
            ])
            self.assertEqual(detect_local(tmp), "5.11.1")

    def test_detect_from_packages_dev(self):
        with tempfile.TemporaryDirectory() as tmp:
            lock = {"packages": [], "packages-dev": [
                {"name": "craftcms/cms", "version": "4.18.8"},
            ]}
            with open(os.path.join(tmp, "composer.lock"), "w") as f:
                json.dump(lock, f)
            self.assertEqual(detect_local(tmp), "4.18.8")

    def test_detect_missing_lock(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                detect_local(tmp)

    def test_detect_no_craft_package(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._write_lock(tmp, [{"name": "psr/log", "version": "3.0.0"}])
            with self.assertRaises(ValueError):
                detect_local(tmp)

    def test_detect_not_a_directory(self):
        with self.assertRaises(ValueError):
            detect_local("/nonexistent/path/xyz")

    def test_read_version_file(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
            f.write("5.11.1\n")
            path = f.name
        try:
            self.assertEqual(read_version_file(path), "5.11.1")
        finally:
            os.unlink(path)


class TestCli(unittest.TestCase):
    def _run(self, *args):
        script = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "craftcms_scanner.py",
        )
        return subprocess.run(
            [sys.executable, script, *args],
            capture_output=True, text=True, timeout=30,
        )

    def test_cli_vulnerable_exit_2(self):
        proc = self._run("--version", "5.11.1")
        self.assertEqual(proc.returncode, 2)
        self.assertIn("grade:      VULNERABLE", proc.stdout)
        self.assertIn("CVE-2026-123488 (9.8, unauthenticated): VULNERABLE", proc.stdout)

    def test_cli_patched_exit_0(self):
        proc = self._run("--version", "5.11.2")
        self.assertEqual(proc.returncode, 0)
        self.assertIn("grade:      PATCHED", proc.stdout)

    def test_cli_unknown_exit_0(self):
        # UNKNOWN is not clean, but it does not change the exit code.
        proc = self._run("--version", "3.9.0")
        self.assertEqual(proc.returncode, 0)
        self.assertIn("grade:      UNKNOWN", proc.stdout)

    def test_cli_missing_args_exit_1(self):
        proc = self._run()
        self.assertEqual(proc.returncode, 2)  # argparse error

    def test_cli_json_output(self):
        proc = self._run("--version", "4.18.8", "--json")
        self.assertEqual(proc.returncode, 2)
        data = json.loads(proc.stdout)
        self.assertEqual(data["grade"], "VULNERABLE")
        self.assertEqual(data["per_cve"]["CVE-2026-123488"], "VULNERABLE")
        self.assertEqual(data["per_cve"]["CVE-2026-123490"], "NOT-AFFECTED")
        self.assertEqual(data["fixed"], "4.18.9")

    def test_cli_list(self):
        proc = self._run("--list")
        self.assertEqual(proc.returncode, 0)
        self.assertIn("Craft 4.x: 4.0.0 through 4.18.8 affected, fixed in 4.18.9", proc.stdout)
        self.assertIn("Craft 5.x: 5.0.0 through 5.11.1 affected, fixed in 5.11.2", proc.stdout)
        self.assertIn("CVE-2026-123490 affects Craft 5 only, from 5.8.17", proc.stdout)

    def test_cli_local(self):
        with tempfile.TemporaryDirectory() as tmp:
            lock = {"packages": [
                {"name": "craftcms/cms", "version": "v5.11.1"},
            ], "packages-dev": []}
            with open(os.path.join(tmp, "composer.lock"), "w") as f:
                json.dump(lock, f)
            proc = self._run("--local", tmp)
            self.assertEqual(proc.returncode, 2)
            self.assertIn("version:    5.11.1", proc.stdout)
            self.assertIn("grade:      VULNERABLE", proc.stdout)

    def test_cli_inventory(self):
        with tempfile.TemporaryDirectory() as tmp:
            inv_path = os.path.join(tmp, "sites.json")
            with open(inv_path, "w") as f:
                json.dump([
                    {"label": "shop", "version": "5.11.1"},
                    {"label": "blog", "version": "5.11.2"},
                ], f)
            proc = self._run("--inventory-json", inv_path)
            self.assertEqual(proc.returncode, 2)
            self.assertIn("[shop]", proc.stdout)
            self.assertIn("[blog]", proc.stdout)
            self.assertIn("grade:      PATCHED", proc.stdout)

    def test_cli_inventory_all_patched_exit_0(self):
        with tempfile.TemporaryDirectory() as tmp:
            inv_path = os.path.join(tmp, "sites.json")
            with open(inv_path, "w") as f:
                json.dump([{"label": "blog", "version": "4.18.9"}], f)
            proc = self._run("--inventory-json", inv_path)
            self.assertEqual(proc.returncode, 0)


class TestTableSanity(unittest.TestCase):
    def test_fixed_versions(self):
        self.assertEqual(FIXED, {4: (4, 18, 9), 5: (5, 11, 2)})

    def test_four_cves_covered(self):
        self.assertEqual(
            set(CVES),
            {"CVE-2026-123488", "CVE-2026-123489",
             "CVE-2026-123490", "CVE-2026-123491"},
        )

    def test_format_version(self):
        self.assertEqual(format_version((5, 11, 2)), "5.11.2")


if __name__ == "__main__":
    unittest.main()
