"""Offline tests for the bounded Zentral core-image derivation."""

from __future__ import annotations

import hashlib
import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "experiments" / "server" / "prepare_core_build.py"
SPEC = importlib.util.spec_from_file_location("prepare_core_build", MODULE_PATH)
assert SPEC and SPEC.loader
core_build = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(core_build)


UPSTREAM_DOCKERFILE = """ARG APP_ENV=dev
ARG APP_VERSION=unknown

FROM python:3.14-trixie AS base-builder
RUN echo common

####
# Build stage 1:
# - install extra APP_ENV requirements
#
FROM base-builder AS dev-builder
COPY ./tests /zentral/tests
FROM base-builder AS aws-builder
RUN pip install aws
FROM base-builder AS gcp-builder
RUN pip install gcp

#####
# Build stage 2:
# - install apt dependencies
#
FROM python:3.14-slim-trixie AS base-runner
RUN echo runner

####
# Build stage 3:
# - run extra APP_ENV setup
#
FROM base-runner AS dev-runner
COPY --from=dev-builder /opt/venv /opt/venv
FROM base-runner AS aws-runner
COPY --from=aws-builder /opt/venv /opt/venv
FROM base-runner AS gcp-runner
COPY --from=gcp-builder /opt/venv /opt/venv

####
# Build stage 4:
# - copy the app
#
FROM ${APP_ENV}-runner AS final
COPY docker-entrypoint.py /zentral/
COPY ./ee /zentral/ee
COPY ./server /zentral/server
COPY ./zentral /zentral/zentral
RUN printf "version = \\\"\\\"\\\"$APP_VERSION\\\"\\\"\\\"\\n" > /zentral/server/base/deployment.py

WORKDIR /zentral
USER zentral
"""
UPSTREAM_LICENSE = b"Apache-2.0 and ZPEL notice\n"
UPSTREAM_REGISTRY = core_build.UPSTREAM_REGISTRY


class CoreBuildTests(unittest.TestCase):
    def _source(self, root: Path) -> tuple[Path, str, str, str]:
        source = root / "zentral"
        source.mkdir()
        (source / "server").mkdir()
        (source / "server" / "realms" / "backends").mkdir(parents=True)
        (source / "zentral").mkdir()
        (source / "ee").mkdir()
        (source / "Dockerfile").write_bytes(UPSTREAM_DOCKERFILE.encode("utf-8"))
        (source / "LICENSE").write_bytes(UPSTREAM_LICENSE)
        (source / core_build.REGISTRY_PATH).write_bytes(UPSTREAM_REGISTRY)
        docker_hash = hashlib.sha256((source / "Dockerfile").read_bytes()).hexdigest()
        license_hash = hashlib.sha256((source / "LICENSE").read_bytes()).hexdigest()
        registry_hash = hashlib.sha256((source / core_build.REGISTRY_PATH).read_bytes()).hexdigest()
        subprocess.run(["git", "init", "--quiet", str(source)], check=True)
        subprocess.run(
            [
                "git",
                "-C",
                str(source),
                "-c",
                "user.name=core-build-test",
                "-c",
                "user.email=core-build-test@example.invalid",
                "add",
                "Dockerfile",
                "LICENSE",
                core_build.REGISTRY_PATH,
            ],
            check=True,
        )
        subprocess.run(
            [
                "git",
                "-C",
                str(source),
                "-c",
                "user.name=core-build-test",
                "-c",
                "user.email=core-build-test@example.invalid",
                "commit",
                "--quiet",
                "-m",
                "fixture",
            ],
            check=True,
        )
        return source, docker_hash, license_hash, registry_hash

    def test_render_removes_non_core_stages_and_ee_copy(self) -> None:
        self.assertEqual(
            core_build.UPSTREAM_DOCKERFILE_SHA256,
            "dd06e76e0b325684c0c07734cfb1b951218678fb454b8af18e719f309c2e94e1",
        )
        self.assertEqual(
            core_build.UPSTREAM_LICENSE_SHA256,
            "00f43b4775da6dcbe63d20b3b2c36e616f35af5595d02c590278e75d9d86793c",
        )
        self.assertEqual(
            core_build.UPSTREAM_REGISTRY_SHA256,
            "d216a4a58acb8258794bd67db64dec5f6a69ebfe8d93d5ebbe1b702e88704cca",
        )
        self.assertEqual(
            core_build.CORE_REGISTRY_SHA256,
            "2c2aceac8fb47a73a418b471a87e0a47e2c852a7f57e7022e27f400aa79b261f",
        )
        rendered = core_build.render_core_dockerfile(UPSTREAM_DOCKERFILE, UPSTREAM_LICENSE, UPSTREAM_REGISTRY)
        self.assertIn("ARG APP_ENV=core", rendered)
        self.assertIn("FROM base-builder AS core-builder", rendered)
        self.assertIn("FROM base-runner AS core-runner", rendered)
        self.assertIn("COPY --from=core-builder /opt/venv /opt/venv", rendered)
        self.assertNotIn("dev-builder", rendered)
        self.assertNotIn("aws-builder", rendered)
        self.assertNotIn("gcp-builder", rendered)
        self.assertNotIn("COPY ./tests", rendered)
        self.assertNotIn("COPY ./ee", rendered)
        self.assertIn("base64 -d > /usr/share/doc/zentral/LICENSE", rendered)
        self.assertNotIn("COPY LICENSE", rendered)
        self.assertIn("/usr/share/doc/zentral/CORE_BUILD_NOTICE.txt", rendered)
        self.assertIn("test ! -e /zentral/ee", rendered)
        self.assertIn("test -d /zentral/server/accounts", rendered)
        self.assertIn("test -d /zentral/server/realms", rendered)
        self.assertIn("test -d /zentral/zentral/contrib/santa", rendered)
        self.assertIn("prepare_core_registry.py", rendered)
        self.assertIn("Core registry input SHA256", rendered)

    def test_registry_narrowing_removes_only_ee_backends(self) -> None:
        narrowed = core_build.narrow_core_registry(UPSTREAM_REGISTRY)
        self.assertEqual(narrowed, core_build.CORE_REGISTRY_NARROWED)
        self.assertIn(b"Modified by azd-santa", narrowed)
        self.assertIn(b"LDAPRealmBackend", narrowed)
        self.assertIn(b'"ldap": LDAPRealmBackend', narrowed)
        self.assertNotIn(b"from realms.backends.openidc", narrowed)
        self.assertNotIn(b"from realms.backends.saml", narrowed)
        self.assertNotIn(b'"openidc":', narrowed)
        self.assertNotIn(b'"saml":', narrowed)
        with self.assertRaises(ValueError):
            core_build.narrow_core_registry(UPSTREAM_REGISTRY + b"\n")

    def test_derivation_is_deterministic_and_does_not_change_source(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source, docker_hash, license_hash, _ = self._source(Path(directory))
            output = source / "Dockerfile.core"
            before = {path: path.read_bytes() for path in source.rglob("*") if path.is_file()}
            with mock.patch.object(core_build, "UPSTREAM_DOCKERFILE_SHA256", docker_hash), mock.patch.object(
                core_build, "UPSTREAM_LICENSE_SHA256", license_hash
            ), mock.patch.object(core_build, "_git_head", return_value=core_build.UPSTREAM_COMMIT):
                first = core_build.derive_core_dockerfile(source, output)
            first_bytes = first.read_bytes()
            first.unlink()
            with mock.patch.object(core_build, "UPSTREAM_DOCKERFILE_SHA256", docker_hash), mock.patch.object(
                core_build, "UPSTREAM_LICENSE_SHA256", license_hash
            ), mock.patch.object(core_build, "_git_head", return_value=core_build.UPSTREAM_COMMIT):
                second = core_build.derive_core_dockerfile(source, output)
            self.assertEqual(first_bytes, second.read_bytes())
            after = {path: path.read_bytes() for path in source.rglob("*") if path.is_file() and path != output}
            self.assertEqual(before, after)

    def test_refuses_existing_output_and_unexpected_license(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source, docker_hash, license_hash, _ = self._source(Path(directory))
            with mock.patch.object(core_build, "_git_head", return_value=core_build.UPSTREAM_COMMIT):
                with self.assertRaises(ValueError):
                    core_build.validate_source(source)
            with mock.patch.object(core_build, "UPSTREAM_DOCKERFILE_SHA256", docker_hash), mock.patch.object(
                core_build, "UPSTREAM_LICENSE_SHA256", license_hash
            ), mock.patch.object(core_build, "_git_head", return_value=core_build.UPSTREAM_COMMIT):
                output = source / "Dockerfile.core"
                output.write_text("sentinel", encoding="utf-8")
                with self.assertRaises(FileExistsError):
                    core_build.derive_core_dockerfile(source, output)
                self.assertEqual(output.read_text(encoding="utf-8"), "sentinel")

    def test_accepts_exact_archive_directory_without_git_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / f"zentral-{core_build.UPSTREAM_COMMIT}"
            source.mkdir()
            (source / "server").mkdir()
            (source / "zentral").mkdir()
            (source / "ee").mkdir()
            (source / "server" / "realms" / "backends").mkdir(parents=True)
            (source / "Dockerfile").write_bytes(UPSTREAM_DOCKERFILE.encode("utf-8"))
            (source / "LICENSE").write_bytes(UPSTREAM_LICENSE)
            (source / core_build.REGISTRY_PATH).write_bytes(UPSTREAM_REGISTRY)
            docker_hash = hashlib.sha256((source / "Dockerfile").read_bytes()).hexdigest()
            license_hash = hashlib.sha256((source / "LICENSE").read_bytes()).hexdigest()
            with mock.patch.object(core_build, "UPSTREAM_DOCKERFILE_SHA256", docker_hash), mock.patch.object(
                core_build, "UPSTREAM_LICENSE_SHA256", license_hash
            ):
                output = core_build.derive_core_dockerfile(source, source / "Dockerfile.core")
            self.assertTrue(output.is_file())
            (source / core_build.REGISTRY_PATH).write_bytes(UPSTREAM_REGISTRY + b"\n")
            with mock.patch.object(core_build, "UPSTREAM_DOCKERFILE_SHA256", docker_hash), mock.patch.object(
                core_build, "UPSTREAM_LICENSE_SHA256", license_hash
            ):
                with self.assertRaisesRegex(ValueError, "core registry"):
                    core_build.validate_source(
                        source,
                        expected_dockerfile_sha256=docker_hash,
                        expected_license_sha256=license_hash,
                    )


if __name__ == "__main__":
    unittest.main()
