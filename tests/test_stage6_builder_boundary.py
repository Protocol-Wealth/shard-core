from __future__ import annotations

import importlib.util
import stat
import subprocess
import sys
import unittest
from types import SimpleNamespace
from unittest import mock
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BUILDER = ROOT / "scripts" / "build-offline-bundle.py"


def _load_builder():
    spec = importlib.util.spec_from_file_location(
        "stage6_build_offline_bundle",
        BUILDER,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load Stage 6 builder")
    module = importlib.util.module_from_spec(spec)
    original_path = sys.path[:]
    sys.path.insert(0, str(ROOT / "scripts"))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path[:] = original_path
    return module


class Stage6BuilderBoundaryTests(unittest.TestCase):
    IMAGE_REPOSITORY = "docker.io/library/python"
    INDEX_DIGEST = (
        "b18992999dbe963a45a8a4da40ac2b1975be1a776d939d098c647482bcad5cba"
    )
    PLATFORM_DIGEST = (
        "28255a3ace7eb4c48bc1b57b90af29e1bc82b4fd6c60614a8e3dce61b87ff941"
    )
    CONFIG_DIGEST = (
        "7e666cfcc7bd4c47b26b7a5ec0116d80e9bc5415ea06c0dc0bd117a50e9fa6c6"
    )

    @classmethod
    def setUpClass(cls):
        cls.builder = (
            _load_builder()
            if sys.version_info[:2] == (3, 11)
            else None
        )

    def _image_reference(self, repository=None, digest=None):
        return (
            f"{repository or self.IMAGE_REPOSITORY}@sha256:"
            f"{digest or self.INDEX_DIGEST}"
        )

    def _image_record(
        self,
        *,
        reported_digest=None,
        repo_digests=None,
        config_digest=None,
        image_os="linux",
        architecture="amd64",
    ):
        if repo_digests is None:
            repo_digests = [
                self._image_reference(),
                self._image_reference(digest=self.PLATFORM_DIGEST),
            ]
        return {
            "Digest": f"sha256:{reported_digest or self.INDEX_DIGEST}",
            "RepoDigests": repo_digests,
            "Id": config_digest or self.CONFIG_DIGEST,
            "Os": image_os,
            "Architecture": architecture,
        }

    def _validate_image_record(self, record, reference=None):
        return self.builder._validate_image_inspection(
            record,
            reference or self._image_reference(),
            expected_repository_digest=self.INDEX_DIGEST,
            expected_platform_manifest_digest=self.PLATFORM_DIGEST,
            expected_image_config_digest=self.CONFIG_DIGEST,
            description="test image",
        )

    @unittest.skipUnless(
        sys.version_info[:2] == (3, 11),
        "Stage 6 builder requires exact Python 3.11",
    )
    def test_parser_requires_approved_tools_and_podman_inputs(self):
        required = {
            action.dest
            for action in self.builder.build_parser()._actions
            if action.required
        }
        self.assertTrue(
            {
                "git_path",
                "expected_git_sha256",
                "python_path",
                "expected_python_sha256",
                "podman_config_root",
                "expected_podman_config_sha256",
                "podman_data_root",
                "podman_runtime_root",
            }.issubset(required)
        )

    @unittest.skipUnless(
        sys.version_info[:2] == (3, 11),
        "Stage 6 builder requires exact Python 3.11",
    )
    def test_podman_environment_is_minimal_and_explicit(self):
        config_root = Path("/approved/config")
        environment = self.builder._podman_environment(
            config_files={
                "containers.conf": (
                    config_root / "containers/containers.conf"
                ),
                "registries.conf": (
                    config_root / "containers/registries.conf"
                ),
                "storage.conf": (
                    config_root / "containers/storage.conf"
                ),
            },
            config_root=config_root,
            data_root=Path("/approved/data"),
            runtime_root=Path("/approved/run"),
            home=Path("/home/ceremony"),
            user="ceremony",
        )

        self.assertEqual(
            set(environment),
            {
                "CONTAINERS_CONF",
                "CONTAINERS_REGISTRIES_CONF",
                "CONTAINERS_STORAGE_CONF",
                "HOME",
                "LANG",
                "LC_ALL",
                "LOGNAME",
                "PATH",
                "PODMAN_NO_PAUSE_PROCESS",
                "TMPDIR",
                "TZ",
                "USER",
                "XDG_CONFIG_HOME",
                "XDG_DATA_HOME",
                "XDG_RUNTIME_DIR",
            },
        )
        for forbidden in (
            "CONTAINERS_CONF_OVERRIDE",
            "CONTAINER_HOST",
            "DOCKER_HOST",
            "PYTHONPATH",
            "SSH_AUTH_SOCK",
            "http_proxy",
            "https_proxy",
        ):
            self.assertNotIn(forbidden, environment)
        self.assertEqual(
            environment["CONTAINERS_CONF"],
            "/approved/config/containers/containers.conf",
        )
        self.assertEqual(
            environment["XDG_CONFIG_HOME"],
            "/approved/config",
        )

    @unittest.skipUnless(
        sys.version_info[:2] == (3, 11),
        "Stage 6 builder requires exact Python 3.11",
    )
    def test_podman_command_binds_effective_storage_roots(self):
        command = self.builder._podman_command(
            Path("/usr/bin/podman"),
            Path("/approved/hooks"),
            Path("/approved/graph"),
            Path("/approved/run"),
        )

        self.assertEqual(
            command,
            [
                "/usr/bin/podman",
                "--root",
                "/approved/graph",
                "--runroot",
                "/approved/run",
                "--remote=false",
                "--hooks-dir",
                "/approved/hooks",
            ],
        )

    @unittest.skipUnless(
        sys.version_info[:2] == (3, 11),
        "Stage 6 builder requires exact Python 3.11",
    )
    def test_hooks_reject_writable_parent_chain(self):
        hooks = Path("/approved/writable/hooks")

        def fake_stat(path):
            mode = 0o777 if path == hooks.parent else 0o755
            return SimpleNamespace(
                st_uid=0,
                st_mode=stat.S_IFDIR | mode,
            )

        with (
            mock.patch.object(
                self.builder,
                "require_real_directory",
                return_value=hooks,
            ),
            mock.patch.object(
                Path,
                "resolve",
                return_value=hooks,
            ),
            mock.patch.object(
                Path,
                "stat",
                new=fake_stat,
            ),
        ):
            with self.assertRaisesRegex(
                self.builder.ReleaseInputError,
                "parent chain must be root-controlled",
            ):
                self.builder._approved_hooks_directory(hooks)

    @unittest.skipUnless(
        sys.version_info[:2] == (3, 11),
        "Stage 6 builder requires exact Python 3.11",
    )
    def test_real_podman_493_image_inspection_passes(self):
        inspection = self._validate_image_record(self._image_record())

        self.assertEqual(
            inspection["reported_digest"],
            self.INDEX_DIGEST,
        )
        self.assertEqual(
            inspection["repository"],
            self.IMAGE_REPOSITORY,
        )

    @unittest.skipUnless(
        sys.version_info[:2] == (3, 11),
        "Stage 6 builder requires exact Python 3.11",
    )
    def test_platform_reported_digest_also_passes(self):
        inspection = self._validate_image_record(
            self._image_record(
                reported_digest=self.PLATFORM_DIGEST,
            )
        )

        self.assertEqual(
            inspection["reported_digest"],
            self.PLATFORM_DIGEST,
        )

    @unittest.skipUnless(
        sys.version_info[:2] == (3, 11),
        "Stage 6 builder requires exact Python 3.11",
    )
    def test_unapproved_reported_digest_is_rejected(self):
        with self.assertRaisesRegex(
            self.builder.ReleaseInputError,
            "reported digest is not approved",
        ):
            self._validate_image_record(
                self._image_record(reported_digest="f" * 64)
            )

    @unittest.skipUnless(
        sys.version_info[:2] == (3, 11),
        "Stage 6 builder requires exact Python 3.11",
    )
    def test_both_exact_repository_digest_references_are_required(self):
        cases = {
            "missing index": [
                self._image_reference(digest=self.PLATFORM_DIGEST),
            ],
            "missing platform": [
                self._image_reference(),
            ],
            "split repositories": [
                self._image_reference(),
                self._image_reference(
                    repository="registry.example/python",
                    digest=self.PLATFORM_DIGEST,
                ),
            ],
            "wrong repository suffix match": [
                self._image_reference(
                    repository="registry.example/python",
                ),
                self._image_reference(
                    repository="registry.example/python",
                    digest=self.PLATFORM_DIGEST,
                ),
            ],
        }
        for name, repo_digests in cases.items():
            with self.subTest(name=name):
                with self.assertRaisesRegex(
                    self.builder.ReleaseInputError,
                    "both approved repository and platform",
                ):
                    self._validate_image_record(
                        self._image_record(
                            repo_digests=repo_digests,
                        )
                    )

    @unittest.skipUnless(
        sys.version_info[:2] == (3, 11),
        "Stage 6 builder requires exact Python 3.11",
    )
    def test_config_os_and_architecture_are_revalidated(self):
        cases = {
            "config": (
                self._image_record(config_digest="e" * 64),
                "image-config digest is not approved",
            ),
            "os": (
                self._image_record(image_os="windows"),
                "must resolve to Linux amd64",
            ),
            "architecture": (
                self._image_record(architecture="arm64"),
                "must resolve to Linux amd64",
            ),
        }
        for name, (record, message) in cases.items():
            with self.subTest(name=name):
                with self.assertRaisesRegex(
                    self.builder.ReleaseInputError,
                    message,
                ):
                    self._validate_image_record(record)

    @unittest.skipUnless(
        sys.version_info[:2] == (3, 11),
        "Stage 6 builder requires exact Python 3.11",
    )
    def test_malformed_repository_digest_inventory_is_rejected(self):
        required = [
            self._image_reference(),
            self._image_reference(digest=self.PLATFORM_DIGEST),
        ]
        for repo_digests in (
            None,
            self._image_reference(),
            [self._image_reference(), 7],
            [*required, ""],
            [*required, "garbage"],
            [*required, self._image_reference()],
        ):
            with self.subTest(repo_digests=repo_digests):
                record = self._image_record()
                record["RepoDigests"] = repo_digests
                with self.assertRaisesRegex(
                    self.builder.ReleaseInputError,
                    "repository digests are invalid",
                ):
                    self._validate_image_record(record)

    @unittest.skipUnless(
        sys.version_info[:2] == (3, 11),
        "Stage 6 builder requires exact Python 3.11",
    )
    def test_noncanonical_image_references_are_rejected(self):
        digest = self.INDEX_DIGEST
        for reference in (
            f"python@sha256:{digest}",
            f"library/python@sha256:{digest}",
            f"docker.io/library/python:3.11@sha256:{digest}",
            f"Docker.io/library/python@sha256:{digest}",
            f"docker.io/library/pythön@sha256:{digest}",
            f"registry.example:0/team/python@sha256:{digest}",
            f"registry.example:70000/team/python@sha256:{digest}",
        ):
            with self.subTest(reference=reference):
                with self.assertRaisesRegex(
                    self.builder.ReleaseInputError,
                    "canonical digest reference",
                ):
                    self._validate_image_record(
                        self._image_record(),
                        reference,
                    )

    @unittest.skipUnless(
        sys.version_info[:2] == (3, 11),
        "Stage 6 builder requires exact Python 3.11",
    )
    def test_reviewed_repository_component_separators_are_accepted(self):
        repository = "registry.example/team/my--image__name"
        record = self._image_record(
            repo_digests=[
                self._image_reference(repository=repository),
                self._image_reference(
                    repository=repository,
                    digest=self.PLATFORM_DIGEST,
                ),
            ]
        )
        inspection = self._validate_image_record(
            record,
            self._image_reference(repository=repository),
        )

        self.assertEqual(inspection["repository"], repository)

    @unittest.skipUnless(
        sys.version_info[:2] == (3, 11),
        "Stage 6 builder requires exact Python 3.11",
    )
    def test_missing_core_image_inspection_fields_fail_closed(self):
        cases = {
            "record": (
                None,
                "inspection record is not an object",
            ),
            "digest": (
                {**self._image_record(), "Digest": None},
                "reported digest is not a string",
            ),
            "config": (
                {**self._image_record(), "Id": None},
                "image-config digest is not a string",
            ),
            "os": (
                {**self._image_record(), "Os": None},
                "must resolve to Linux amd64",
            ),
            "architecture": (
                {**self._image_record(), "Architecture": None},
                "must resolve to Linux amd64",
            ),
        }
        for name, (record, message) in cases.items():
            with self.subTest(name=name):
                with self.assertRaisesRegex(
                    self.builder.ReleaseInputError,
                    message,
                ):
                    self._validate_image_record(record)

    @unittest.skipUnless(
        sys.version_info[:2] == (3, 11),
        "Stage 6 builder requires exact Python 3.11",
    )
    def test_post_build_image_identity_is_immutable(self):
        initial = self._validate_image_record(self._image_record())
        build_environment = {
            "observed_image_digest": initial["reported_digest"],
            "repository_digests": initial["repository_digests"],
        }

        reordered = {
            **initial,
            "repository_digests": list(
                reversed(initial["repository_digests"])
            ),
        }
        self.builder._assert_image_inspection_identity_unchanged(
            build_environment,
            reordered,
        )

        changed_digest = {
            **initial,
            "reported_digest": self.PLATFORM_DIGEST,
        }
        with self.assertRaisesRegex(
            self.builder.ReleaseInputError,
            "reported digest changed",
        ):
            self.builder._assert_image_inspection_identity_unchanged(
                build_environment,
                changed_digest,
            )

        alias = self._image_reference(
            repository="registry.example/team/python",
        )
        for changed_inventory in (
            initial["repository_digests"][:-1],
            [*initial["repository_digests"], alias],
        ):
            with self.subTest(inventory=changed_inventory):
                with self.assertRaisesRegex(
                    self.builder.ReleaseInputError,
                    "repository digests changed",
                ):
                    self.builder._assert_image_inspection_identity_unchanged(
                        build_environment,
                        {
                            **initial,
                            "repository_digests": changed_inventory,
                        },
                    )

    @unittest.skipUnless(
        sys.version_info[:2] == (3, 11),
        "Stage 6 builder requires exact Python 3.11",
    )
    def test_single_platform_digest_may_equal_repository_digest(self):
        record = self._image_record(
            repo_digests=[self._image_reference()],
        )
        inspection = self.builder._validate_image_inspection(
            record,
            self._image_reference(),
            expected_repository_digest=self.INDEX_DIGEST,
            expected_platform_manifest_digest=self.INDEX_DIGEST,
            expected_image_config_digest=self.CONFIG_DIGEST,
            description="test image",
        )

        self.assertEqual(
            inspection["reported_digest"],
            self.INDEX_DIGEST,
        )

    def test_legacy_builder_and_source_installer_fail_closed(self):
        for path, expected in (
            (
                ROOT / "scripts/build-offline-bundle.sh",
                "host-native offline bundle builder is permanently disabled",
            ),
            (
                ROOT / "install.sh",
                "source-tree ceremony installer is disabled",
            ),
        ):
            result = subprocess.run(
                ["bash", str(path)],
                capture_output=True,
                check=False,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(expected, result.stderr)

    def test_readme_names_only_python_builder_as_canonical(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        ceremony = readme.split(
            "### Ceremony / air-gapped host",
            1,
        )[1].split("## Guided mode", 1)[0]
        self.assertIn(
            "The only ceremony candidate builder is",
            ceremony,
        )
        self.assertIn(
            "python3.11 scripts/build-offline-bundle.py",
            ceremony,
        )
        self.assertIn("UNAPPROVED-CANDIDATE", ceremony)
        self.assertNotIn(
            "bash scripts/build-offline-bundle.sh\n",
            ceremony,
        )


if __name__ == "__main__":
    unittest.main()
