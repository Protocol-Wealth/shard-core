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
    @classmethod
    def setUpClass(cls):
        cls.builder = (
            _load_builder()
            if sys.version_info[:2] == (3, 11)
            else None
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
