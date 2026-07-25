from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = ROOT / "scripts" / "validate-release-wheels.py"


def _write_wheel(
    directory: Path,
    name: str,
    *,
    version: str = "1.0",
    requires: tuple[str, ...] = (),
    extras: tuple[str, ...] = (),
) -> Path:
    normalized = name.replace("-", "_")
    wheel_path = directory / (
        f"{normalized}-{version}-py3-none-any.whl"
    )
    dist_info = f"{normalized}-{version}.dist-info"
    metadata = [
        "Metadata-Version: 2.1",
        f"Name: {name}",
        f"Version: {version}",
        *(f"Provides-Extra: {extra}" for extra in extras),
        *(
            f"Requires-Dist: {requirement}"
            for requirement in requires
        ),
        "",
        "",
    ]
    wheel_metadata = [
        "Wheel-Version: 1.0",
        "Generator: shard-core-stage6-test",
        "Root-Is-Purelib: true",
        "Tag: py3-none-any",
        "",
    ]

    with zipfile.ZipFile(wheel_path, "w") as archive:
        archive.writestr(
            f"{dist_info}/METADATA",
            "\n".join(metadata),
        )
        archive.writestr(
            f"{dist_info}/WHEEL",
            "\n".join(wheel_metadata),
        )

    return wheel_path


class Stage6ReleaseValidationTests(unittest.TestCase):
    def _run_validator(
        self,
        *,
        project_requires: tuple[str, ...],
        project_extras: tuple[str, ...],
        dependency_extras: tuple[str, ...],
    ) -> subprocess.CompletedProcess[str]:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        runtime_wheelhouse = root / "runtime"
        runtime_wheelhouse.mkdir()

        _write_wheel(
            runtime_wheelhouse,
            "demo-dependency",
            extras=dependency_extras,
        )
        project_wheel = _write_wheel(
            root,
            "shard-core",
            requires=project_requires,
            extras=project_extras,
        )

        return subprocess.run(
            [
                sys.executable,
                str(VALIDATOR),
                "--runtime-wheelhouse",
                str(runtime_wheelhouse),
                "--project-wheel",
                str(project_wheel),
                "--python-version",
                "3.9",
                "--project-extra",
                "slip39",
            ],
            check=False,
            capture_output=True,
            text=True,
        )

    def test_declared_transitive_extra_is_accepted(self):
        result = self._run_validator(
            project_requires=(
                'demo-dependency[feature]>=1; extra == "slip39"',
            ),
            project_extras=("slip39",),
            dependency_extras=("feature",),
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("validated 2 wheels", result.stdout)

    def test_undeclared_transitive_extra_is_rejected(self):
        result = self._run_validator(
            project_requires=(
                'demo-dependency[feature]>=1; extra == "slip39"',
            ),
            project_extras=("slip39",),
            dependency_extras=(),
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "demo-dependency does not declare requested extra: feature",
            result.stderr,
        )

    def test_undeclared_project_extra_is_rejected(self):
        result = self._run_validator(
            project_requires=(
                'demo-dependency>=1; extra == "slip39"',
            ),
            project_extras=(),
            dependency_extras=(),
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "project does not declare requested extra: slip39",
            result.stderr,
        )


if __name__ == "__main__":
    unittest.main()
