import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
EXPECTED_ACTIONS = {
    "actions/checkout@11d5960a326750d5838078e36cf38b85af677262",
    "actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065",
}
EXPECTED_RUNTIME_HASHES = {
    "pycryptodome": "c8987bd3307a39bc03df5c8e0e3d8be0c4c3518b7f044b0f4c15d1aa78f52575",
    "shamir-mnemonic": "188c6b5bd00d5e756e12e2b186c3cb7c98ff7ff44df608d4c1d2077f6b6e730f",
    "mnemonic": "acd2168872d0379e7a10873bb3e12bf6c91b35de758135c4fbd1015ef18fafc5",
}


def _locked(path: Path) -> dict[str, tuple[str, str]]:
    result = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        name_version, digest = line.split(" --hash=sha256:", 1)
        name, version = name_version.split("==", 1)
        result[name] = (version, digest)
    return result


class ReleaseAssuranceTests(unittest.TestCase):
    def test_package_and_module_versions_match(self):
        project = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        package = (ROOT / "src/shard_core/__init__.py").read_text(encoding="utf-8")
        project_version = re.search(r'^version = "([^"]+)"$', project, re.MULTILINE).group(1)
        package_version = re.search(r'^__version__ = "([^"]+)"$', package, re.MULTILINE).group(1)
        self.assertEqual(project_version, package_version)

    def test_runtime_lock_matches_reviewed_hashes_and_pins(self):
        pins = {}
        for line in (ROOT / "release/ceremony-requirements-linux-x86_64.in").read_text(encoding="utf-8").splitlines():
            if line and not line.startswith("#"):
                name, version = line.split("==", 1)
                pins[name] = version
        locked = _locked(ROOT / "release/ceremony-requirements-linux-x86_64.txt")
        self.assertEqual(set(locked), set(pins))
        self.assertEqual({name: value[0] for name, value in locked.items()}, pins)
        self.assertEqual({name: value[1] for name, value in locked.items()}, EXPECTED_RUNTIME_HASHES)

    def test_build_tool_lock_is_complete_and_hashed(self):
        locked = _locked(ROOT / "release/build-requirements.txt")
        self.assertEqual(
            set(locked),
            {"pip", "build", "setuptools", "wheel", "packaging", "pyproject-hooks"},
        )
        for version, digest in locked.values():
            self.assertRegex(version, r"^[0-9]+(?:\.[0-9]+)+$")
            self.assertRegex(digest, r"^[0-9a-f]{64}$")

    def test_legacy_builder_is_disabled(self):
        script = (
            ROOT / "scripts/build-offline-bundle.sh"
        ).read_text(encoding="utf-8")
        self.assertIn("permanently disabled", script)
        self.assertIn("build-offline-bundle.py --help", script)
        self.assertNotIn("pip install", script)
        self.assertNotIn("pip download", script)
        result = subprocess.run(
            ["bash", str(ROOT / "scripts/build-offline-bundle.sh")],
            capture_output=True,
            check=False,
            text=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("UNAPPROVED-CANDIDATE", result.stderr)

    def test_lock_generator_has_fixed_target_and_fresh_review_dir(self):
        generator = (ROOT / "scripts/generate-ceremony-lock.sh").read_text(encoding="utf-8")
        for expected in (
            "--platform manylinux2014_x86_64",
            "--implementation cp",
            "--python-version 39",
            "--abi abi3",
            "review directory must not already exist",
            "review wheels retained",
        ):
            self.assertIn(expected, generator)
        self.assertNotIn("rm -rf", generator)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks unavailable")
    def test_offline_installer_rejects_dangling_target_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "install-target"
            target.symlink_to(root / "missing")
            result = subprocess.run(
                ["bash", str(ROOT / "release/install-offline.sh"), str(target)],
                capture_output=True,
                check=False,
                text=True,
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("refusing existing installation target", result.stderr)

    def test_offline_installer_rejects_unlisted_file(self):
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory)
            installer = bundle / "install-offline.sh"
            installer.write_bytes((ROOT / "release/install-offline.sh").read_bytes())
            expected = bundle / "expected.txt"
            expected.write_text("expected", encoding="utf-8")
            digest = hashlib.sha256(expected.read_bytes()).hexdigest()
            (bundle / "SHA256SUMS").write_text(
                f"{digest}  expected.txt\n", encoding="utf-8"
            )
            (bundle / "unlisted.txt").write_text("unexpected", encoding="utf-8")
            result = subprocess.run(
                ["bash", str(installer), str(bundle / "target")],
                capture_output=True,
                check=False,
                text=True,
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("inventory differs", result.stderr)

    def test_sbom_renderer_escapes_values_and_lists_build_tools(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "sbom.json"
            subprocess.run(
                [
                    "python3",
                    str(ROOT / "scripts/render-release-sbom.py"),
                    "--output", str(output),
                    "--bundle-name", 'bundle-\"quoted\"',
                    "--version", "0.2.0rc1",
                    "--source-rev", "a" * 40,
                    "--source-describe", 'tag-\"quoted\"',
                    "--source-archive-sha256", "b" * 64,
                    "--created", "2026-07-24T00:00:00Z",
                    "--runtime-lock", str(ROOT / "release/ceremony-requirements-linux-x86_64.txt"),
                    "--build-lock", str(ROOT / "release/build-requirements.txt"),
                ],
                check=True,
            )
            document = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(document["name"], 'bundle-\"quoted\"')
        purposes = {package["primaryPackagePurpose"] for package in document["packages"]}
        self.assertEqual(purposes, {"APPLICATION", "LIBRARY", "BUILD_TOOL"})
        self.assertEqual(len(document["packages"]), 10)

    def test_ci_pins_every_action_to_reviewed_sha(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        action_refs = set(re.findall(r"uses: (actions/(?:checkout|setup-python)@[0-9a-f]{40})", workflow))
        self.assertEqual(action_refs, EXPECTED_ACTIONS)
        self.assertNotRegex(workflow, r"uses: actions/(?:checkout|setup-python)@v")

    def test_ci_runs_optimized_and_stage6_contract_paths(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        self.assertIn("'.[test]'", workflow)
        self.assertIn("python -O -m unittest", workflow)
        self.assertIn("python scripts/build-offline-bundle.py --help", workflow)
        self.assertIn("tests.test_stage6_builder_boundary", workflow)
        self.assertIn("legacy builder unexpectedly succeeded", workflow)
        self.assertNotIn("Build Linux x86_64 ceremony bundle", workflow)

    def test_top_level_installer_never_invokes_package_index(self):
        installer = (ROOT / "install.sh").read_text(encoding="utf-8")
        self.assertNotIn("pip install", installer)
        self.assertNotIn("pipx install", installer)
        self.assertIn("never contacts a package index", installer)
        self.assertIn("source-tree ceremony installer is disabled", installer)
        self.assertNotIn('exec "${bundles[0]}/install-offline.sh"', installer)


if __name__ == "__main__":
    unittest.main()
