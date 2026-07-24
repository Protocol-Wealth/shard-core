from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]


class ReleaseAssuranceTests(unittest.TestCase):
    def test_package_and_module_versions_match(self):
        project = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        package = (ROOT / "src/shard_core/__init__.py").read_text(
            encoding="utf-8"
        )
        project_version = re.search(
            r'^version = "([^"]+)"$', project, re.MULTILINE
        ).group(1)
        package_version = re.search(
            r'^__version__ = "([^"]+)"$', package, re.MULTILINE
        ).group(1)
        self.assertEqual(project_version, package_version)
        self.assertEqual(project_version, "0.2.0rc1")

    def test_test_extra_declares_slip39_dependencies(self):
        project = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        test_extra = re.search(
            r'^test = \[(.*?)\]$', project, re.MULTILINE | re.DOTALL
        ).group(1)
        self.assertIn("shamir-mnemonic", test_extra)
        self.assertIn("mnemonic", test_extra)

    def test_ceremony_inputs_are_exactly_pinned(self):
        pins = (
            ROOT / "release/ceremony-requirements-linux-x86_64.in"
        ).read_text(encoding="utf-8")
        requirements = [
            line for line in pins.splitlines()
            if line and not line.startswith("#")
        ]
        self.assertEqual(len(requirements), 3)
        for requirement in requirements:
            self.assertRegex(requirement, r"^[a-z0-9-]+==[a-zA-Z0-9.]+$")

    def test_offline_installer_is_hash_locked(self):
        installer = (
            ROOT / "release/install-offline.sh"
        ).read_text(encoding="utf-8")
        self.assertIn("--no-index", installer)
        self.assertIn("--find-links", installer)
        self.assertIn("--require-hashes", installer)
        self.assertIn("sha256sum -c SHA256SUMS", installer)

    def test_top_level_installer_never_invokes_package_index(self):
        installer = (ROOT / "install.sh").read_text(encoding="utf-8")
        self.assertNotIn("pip install", installer)
        self.assertNotIn("pipx install", installer)
        self.assertIn("never contacts a package index", installer)

    def test_ci_runs_optimized_and_offline_paths(self):
        workflow = (
            ROOT / ".github/workflows/ci.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("'.[test]'", workflow)
        self.assertIn("python -O -m unittest", workflow)
        self.assertIn("scripts/build-offline-bundle.sh", workflow)
        self.assertIn("PIP_NO_INDEX=1", workflow)


if __name__ == "__main__":
    unittest.main()
