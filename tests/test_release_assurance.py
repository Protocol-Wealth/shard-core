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
        self.assertEqual(project_version, "0.3.0")

    def test_stable_release_metadata_and_community_files(self):
        project = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        cli = (ROOT / "src/shard_core/cli.py").read_text(encoding="utf-8")
        self.assertIn(
            'Homepage = "https://protocolwealthllc.com/opensource/encryption"',
            project,
        )
        self.assertIn(
            'Security = "https://github.com/Protocol-Wealth/shard-core/security/policy"',
            project,
        )
        self.assertIn('requires = ["setuptools>=77"]', project)
        self.assertIn('license = "Apache-2.0 OR MIT-0"', project)
        self.assertIn(
            'license-files = ["LICENSE", "LICENSE-MIT-0"]',
            project,
        )
        self.assertNotIn("license = { text =", project)
        self.assertNotIn("reveals NOTHING", cli)
        self.assertNotIn("fewer reveal nothing", cli)
        self.assertIn(
            "Share headers and ciphertext length still expose limited metadata.",
            cli,
        )
        for relative in (
            "CHANGELOG.md",
            "CODE_OF_CONDUCT.md",
            "CONTRIBUTING.md",
            "SUPPORT.md",
            "CITATION.cff",
            "RELEASING.md",
            ".github/ISSUE_TEMPLATE/config.yml",
            ".github/ISSUE_TEMPLATE/bug_report.yml",
            ".github/ISSUE_TEMPLATE/feature_request.yml",
            ".github/pull_request_template.md",
        ):
            self.assertTrue((ROOT / relative).is_file(), relative)

    def test_pypi_publish_uses_manual_oidc_trusted_publishing(self):
        workflow = (
            ROOT / ".github/workflows/publish-pypi.yml"
        ).read_text(encoding="utf-8")
        build_job, publish_job = workflow.split("\n  publish:\n", 1)
        self.assertIn("workflow_dispatch:", workflow)
        self.assertNotIn("on:\n  release:", workflow)
        self.assertIn("contents: read", workflow)
        self.assertIn("persist-credentials: false", workflow)
        self.assertIn("environment:\n      name: pypi", workflow)
        self.assertIn("--require-hashes", workflow)
        self.assertIn("release/build-requirements.txt", workflow)
        self.assertIn("scripts/validate-release-tag.py", workflow)
        self.assertIn("python -m build --no-isolation", workflow)
        self.assertIn(
            "actions/upload-artifact@"
            "ea165f8d65b6e75b540449e92b4886f43607fa02",
            build_job,
        )
        self.assertNotIn("id-token: write", build_job)
        self.assertNotIn("actions/checkout@", publish_job)
        self.assertIn("needs: build", publish_job)
        self.assertIn("id-token: write", publish_job)
        self.assertIn(
            "actions/download-artifact@"
            "d3f86a106a0bac45b974a628896c90dbdf5c8093",
            publish_job,
        )
        self.assertIn(
            "pypa/gh-action-pypi-publish@"
            "ba38be9e461d3875417946c167d0b5f3d385a247",
            publish_job,
        )
        self.assertNotRegex(
            workflow,
            r"pypa/gh-action-pypi-publish@(?:release/)?v",
        )
        self.assertNotIn("password:", workflow)

    def test_release_tag_validator_enforces_exact_final_version(self):
        script = ROOT / "scripts/validate-release-tag.py"
        valid = subprocess.run(
            [
                "python3",
                str(script),
                "--tag",
                "v0.3.0",
                "--pyproject",
                str(ROOT / "pyproject.toml"),
            ],
            capture_output=True,
            check=False,
            text=True,
        )
        self.assertEqual(valid.returncode, 0, valid.stderr)
        self.assertEqual(valid.stdout.strip(), "0.3.0")

        for invalid in (
            "0.3.0",
            "v0.3",
            "v0.3.0rc1",
            "v0.3.0+local",
            "v0.3.0.1",
            "v0x3x0",
            "v0.3.0evil",
        ):
            rejected = subprocess.run(
                [
                    "python3",
                    str(script),
                    "--tag",
                    invalid,
                    "--pyproject",
                    str(ROOT / "pyproject.toml"),
                ],
                capture_output=True,
                check=False,
                text=True,
            )
            self.assertNotEqual(rejected.returncode, 0, invalid)

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
        self.assertIn("isolated rootless Podman build boundary", result.stderr)

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
                    "--version", "0.3.0",
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
        self.assertIn("permissions:\n  contents: read", workflow)
        self.assertEqual(
            workflow.count("persist-credentials: false"),
            workflow.count("actions/checkout@"),
        )

    def test_ci_runs_optimized_and_stage6_contract_paths(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        self.assertNotIn("'.[test]'", workflow)
        self.assertNotIn("'.[dev]'", workflow)
        self.assertIn("--require-hashes", workflow)
        self.assertIn("release/ci-requirements.txt", workflow)
        self.assertIn("python -m build --wheel --no-isolation", workflow)
        self.assertIn("python -O -m unittest", workflow)
        self.assertIn("python scripts/build-offline-bundle.py --help", workflow)
        self.assertIn("tests.test_stage6_builder_boundary", workflow)
        self.assertIn("legacy builder unexpectedly succeeded", workflow)
        self.assertNotIn("Build Linux x86_64 ceremony bundle", workflow)
        self.assertIn(
            "Hosted CI is test evidence, not candidate provenance",
            workflow,
        )

    def test_top_level_installer_dispatches_only_to_built_bundle(self):
        installer = (ROOT / "install.sh").read_text(encoding="utf-8")
        self.assertNotIn("pip install", installer)
        self.assertNotIn("pipx install", installer)
        self.assertIn('"$DIST"/shard-core-*-offline', installer)
        self.assertIn('exec "$installer" "$TARGET"', installer)
        self.assertIn('-L "${bundles[0]}"', installer)
        self.assertIn('-L "$installer"', installer)

    @unittest.skipUnless(
        hasattr(os, "symlink"),
        "symlinks unavailable",
    )
    def test_top_level_installer_refuses_symlinked_bundle_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            dispatcher = root / "install.sh"
            dispatcher.write_text(
                (ROOT / "install.sh").read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            dispatcher.chmod(0o755)

            fake_bundle = root / "fake-bundle"
            fake_bundle.mkdir()
            marker = root / "attacker-installer-ran"
            fake_installer = fake_bundle / "install-offline.sh"
            fake_installer.write_text(
                f"#!/usr/bin/env bash\ntouch {marker}\n",
                encoding="utf-8",
            )
            fake_installer.chmod(0o755)

            dist = root / "dist"
            dist.mkdir()
            bundle_link = (
                dist
                / (
                    "shard-core-0.3.0-offline-"
                    "cp39-abi3-manylinux_2_17_x86_64"
                )
            )
            bundle_link.symlink_to(
                fake_bundle,
                target_is_directory=True,
            )

            completed = subprocess.run(
                ["bash", str(dispatcher), str(root / "target")],
                capture_output=True,
                check=False,
                text=True,
            )

            self.assertNotEqual(completed.returncode, 0)
            self.assertIn(
                "refusing symlinked or non-directory offline bundle",
                completed.stderr,
            )
            self.assertFalse(marker.exists())

    @unittest.skipUnless(
        hasattr(os, "symlink"),
        "symlinks unavailable",
    )
    def test_top_level_installer_refuses_symlinked_dist_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            dispatcher = root / "install.sh"
            dispatcher.write_text(
                (ROOT / "install.sh").read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            dispatcher.chmod(0o755)

            attacker_root = root / "attacker"
            fake_bundle = (
                attacker_root
                / (
                    "shard-core-0.3.0-offline-"
                    "cp39-abi3-manylinux_2_17_x86_64"
                )
            )
            fake_bundle.mkdir(parents=True)
            marker = root / "attacker-installer-ran"
            fake_installer = fake_bundle / "install-offline.sh"
            fake_installer.write_text(
                f"#!/usr/bin/env bash\ntouch {marker}\n",
                encoding="utf-8",
            )
            fake_installer.chmod(0o755)
            (root / "dist").symlink_to(
                attacker_root,
                target_is_directory=True,
            )

            completed = subprocess.run(
                ["bash", str(dispatcher), str(root / "target")],
                capture_output=True,
                check=False,
                text=True,
            )

            self.assertNotEqual(completed.returncode, 0)
            self.assertIn(
                "refusing symlinked offline bundle directory",
                completed.stderr,
            )
            self.assertFalse(marker.exists())

    def test_ci_dependency_lock_is_exact_and_hashed(self):
        locked = _locked(ROOT / "release/ci-requirements.txt")
        self.assertEqual(
            set(locked),
            {
                "pycryptodome",
                "shamir-mnemonic",
                "mnemonic",
                "packaging",
            },
        )
        for version, digest in locked.values():
            self.assertRegex(version, r"^[0-9]+(?:\.[0-9]+)+$")
            self.assertRegex(digest, r"^[0-9a-f]{64}$")
        runtime = _locked(
            ROOT
            / "release/locks/"
            "runtime-cp39-abi3-manylinux_2_17_x86_64.txt"
        )
        build = _locked(ROOT / "release/build-requirements.txt")
        for name in ("pycryptodome", "shamir-mnemonic", "mnemonic"):
            self.assertEqual(locked[name], runtime[name])
        self.assertEqual(locked["packaging"], build["packaging"])

    def test_builder_materializes_installable_approved_candidate(self):
        builder = (
            ROOT / "scripts/build-offline-bundle.py"
        ).read_text(encoding="utf-8")
        self.assertIn('"release_status": "approved_candidate"', builder)
        self.assertIn('"APPROVED-CANDIDATE.txt"', builder)
        self.assertIn('bundle / "install-offline.sh"', builder)
        self.assertIn('bundle / "VERIFY.md"', builder)
        self.assertNotIn("unapproved_candidate", builder)
        self.assertNotIn("UNAPPROVED-CANDIDATE", builder)
        self.assertNotIn("producer authentication", builder.lower())

    def test_offline_installer_refuses_dangling_target_symlink(self):
        installer = (
            ROOT / "release/install-offline.sh"
        ).read_text(encoding="utf-8")
        self.assertIn('[[ -e "$TARGET" || -L "$TARGET" ]]', installer)


if __name__ == "__main__":
    unittest.main()
