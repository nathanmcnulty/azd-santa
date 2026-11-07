"""Offline tests for the bounded Zentral core-image derivation."""

from __future__ import annotations

import hashlib
import ast
import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from types import SimpleNamespace


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
UPSTREAM_STORES_BACKENDS = b"""from importlib import import_module
import logging
from django.db import models


logger = logging.getLogger("zentral.core.events.stores.all")


class StoreBackend(models.TextChoices):
    ClickHouse = "CLICKHOUSE", "ClickHouse"
    Datadog = "DATADOG", "Datadog"
    Elasticsearch = "ELASTICSEARCH", "Elasticsearch"
    HTTP = "HTTP", "HTTP"
    Kinesis = "KINESIS", "Kinesis"
    OpenSearch = "OPENSEARCH", "OpenSearch"
    Panther = "PANTHER", "Panther"
    S3Parquet = "S3_PARQUET", "S3 Parquet"
    Snowflake = "SNOWFLAKE", "Snowflake"
    Splunk = "SPLUNK", "Splunk"
    SumoLogic = "SUMO_LOGIC", "Sumo Logic"


def get_store_backend(store, load=False):
    backend = StoreBackend(store.backend)
    try:
        module = import_module(f"zentral.core.stores.backends.{backend.value.lower()}")
        backend_cls = getattr(module, f"{backend.name}Store")
    except (ImportError, AttributeError):
        logger.exception("Could not load store backend %s", backend)
    return backend_cls(store, load)
"""
UPSTREAM_STORES_SERIALIZERS = b"""from django.utils.text import slugify
from rest_framework import serializers
from accounts.models import Group
from zentral.core.events.serializers import EventFilterSetSerializer
from zentral.core.stores.backends.all import StoreBackend
from zentral.core.stores.backends.clickhouse import ClickHouseStoreSerializer
from zentral.core.stores.backends.datadog import DatadogStoreSerializer
from zentral.core.stores.backends.es_os_base import ESOSStoreSerializer
from zentral.core.stores.backends.http import HTTPStoreSerializer
from zentral.core.stores.backends.kinesis import KinesisStoreSerializer
from zentral.core.stores.backends.opensearch import OpenSearchStoreSerializer
from zentral.core.stores.backends.panther import PantherStoreSerializer
from zentral.core.stores.backends.s3_parquet import S3ParquetStoreSerializer
from zentral.core.stores.backends.snowflake import SnowflakeStoreSerializer
from zentral.core.stores.backends.splunk import SplunkStoreSerializer
from zentral.core.stores.backends.sumo_logic import SumoLogicStoreSerializer
from .models import Store


class StoreSerializer(serializers.ModelSerializer):
    event_filters = EventFilterSetSerializer(required=False)
    clickhouse_kwargs = ClickHouseStoreSerializer(source="get_clickhouse_kwargs", required=False, allow_null=True)
    datadog_kwargs = DatadogStoreSerializer(source="get_datadog_kwargs", required=False, allow_null=True)
    elasticsearch_kwargs = ESOSStoreSerializer(source="get_elasticsearch_kwargs", required=False, allow_null=True)
    http_kwargs = HTTPStoreSerializer(source="get_http_kwargs", required=False, allow_null=True)
    kinesis_kwargs = KinesisStoreSerializer(source="get_kinesis_kwargs", required=False, allow_null=True)
    opensearch_kwargs = OpenSearchStoreSerializer(source="get_opensearch_kwargs", required=False, allow_null=True)
    panther_kwargs = PantherStoreSerializer(source="get_panther_kwargs", required=False, allow_null=True)
    s3_parquet_kwargs = S3ParquetStoreSerializer(source="get_s3_parquet_kwargs", required=False, allow_null=True)
    snowflake_kwargs = SnowflakeStoreSerializer(source="get_snowflake_kwargs", required=False, allow_null=True)
    splunk_kwargs = SplunkStoreSerializer(source="get_splunk_kwargs", required=False, allow_null=True)
    sumo_logic_kwargs = SumoLogicStoreSerializer(source="get_sumo_logic_kwargs", required=False, allow_null=True)

    class Meta:
        model = Store
        fields = (
            "id",
            "provisioning_uid",
            "name",
            "description",
            "admin_console",
            "events_url_authorized_roles",
            "event_filters",
            "created_at",
            "updated_at",
            # backends
            "backend",
            "clickhouse_kwargs",
            "datadog_kwargs",
            "elasticsearch_kwargs",
            "http_kwargs",
            "kinesis_kwargs",
            "opensearch_kwargs",
            "panther_kwargs",
            "s3_parquet_kwargs",
            "snowflake_kwargs",
            "splunk_kwargs",
            "sumo_logic_kwargs",
        )

    def validate(self, data):
        data = super().validate(data)
        # slug
        slug = slugify(data["name"])
        slug_unicity_qs = Store.objects.filter(slug=slug)
        if self.instance and self.instance.pk:
            slug_unicity_qs = slug_unicity_qs.exclude(pk=self.instance.pk)
        if slug_unicity_qs.exists():
            raise serializers.ValidationError(
                {"name": "A store with the same slugified version of this name already exists"}
            )
        data["slug"] = slug
        # backend
        backend = StoreBackend(data["backend"])
        # backend kwargs
        backend_slug = backend.value.lower()
        data["backend_kwargs"] = data.pop(f"get_{backend_slug}_kwargs", None)
        if not data["backend_kwargs"]:
            raise serializers.ValidationError(
                {f"{backend_slug}_kwargs": "This field is required."}
            )
        # other backends kwargs
        for other_backend in StoreBackend:
            if other_backend == backend:
                continue
            other_backend_slug = other_backend.value.lower()
            if data.pop(f"get_{other_backend_slug}_kwargs", None):
                raise serializers.ValidationError(
                    {f"{other_backend_slug}_kwargs": "This field cannot be set for this backend."}
                )
        return data

    def create(self, validated_data):
        backend_kwargs = validated_data.pop("backend_kwargs", {})
        validated_data["backend_kwargs"] = {}
        store = super().create(validated_data)
        store.set_backend_kwargs(backend_kwargs)
        store.save()
        return store

    def update(self, instance, validated_data):
        backend_kwargs = validated_data.pop("backend_kwargs", {})
        store = super().update(instance, validated_data)
        store.set_backend_kwargs(backend_kwargs)
        store.save()
        return store

    def to_representation(self, instance):
        ret = super().to_representation(instance)
        if instance.provisioning_uid:
            for field in list(ret.keys()):
                if field == "backend" or "kwargs" in field:
                    ret.pop(field)
        else:
            # other backends kwargs
            for other_backend in StoreBackend:
                if other_backend == ret["backend"]:
                    continue
                other_backend_slug = other_backend.value.lower()
                ret.pop(f"{other_backend_slug}_kwargs", None)
        return ret


class StoreProvisioningSerializer(StoreSerializer):
    # for provisioning, reference roles by provisioning_uid, not pk
    events_url_authorized_roles = serializers.SlugRelatedField(
        many=True,
        queryset=Group.objects.filter(provisioned_role__isnull=False),
        slug_field="provisioned_role__provisioning_uid",
        required=False,
    )
"""


class CoreBuildTests(unittest.TestCase):
    def setUp(self):
        # These small fixtures isolate the existing core derivation. Operator
        # policy packaging and actual Django behavior have separate acceptance.
        layer = mock.patch.object(core_build, '_operator_layer', return_value=('pass\n', 'a' * 64))
        limits_layer = mock.patch.object(core_build, '_request_limits_layer', return_value=('pass\n', 'b' * 64))
        limits_layer.start()
        self.addCleanup(limits_layer.stop)
        layer.start()
        self.addCleanup(layer.stop)

    def _source(self, root: Path) -> tuple[Path, str, str, str]:
        source = root / "zentral"
        source.mkdir()
        (source / "server").mkdir()
        (source / "server" / "realms" / "backends").mkdir(parents=True)
        (source / "zentral").mkdir()
        (source / "zentral" / "core" / "stores" / "backends").mkdir(parents=True)
        (source / "ee").mkdir()
        (source / "Dockerfile").write_bytes(UPSTREAM_DOCKERFILE.encode("utf-8"))
        (source / "LICENSE").write_bytes(UPSTREAM_LICENSE)
        (source / core_build.REGISTRY_PATH).write_bytes(UPSTREAM_REGISTRY)
        (source / core_build.STORES_BACKENDS_PATH).write_bytes(UPSTREAM_STORES_BACKENDS)
        (source / core_build.STORES_SERIALIZERS_PATH).write_bytes(UPSTREAM_STORES_SERIALIZERS)
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
                core_build.STORES_BACKENDS_PATH,
                core_build.STORES_SERIALIZERS_PATH,
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
        self.assertEqual(
            hashlib.sha256(UPSTREAM_STORES_BACKENDS).hexdigest(),
            "7db6c71eb508bce42d92803c9dc83799fd7d5dbacec577a47f98aaf06b0a5d4a",
        )
        self.assertEqual(
            core_build.CORE_STORES_BACKENDS_SHA256,
            "3a61216f59b69808a926e7063737004fc0b60d4e8642427f22323eca61a7a09b",
        )
        self.assertEqual(
            hashlib.sha256(UPSTREAM_STORES_SERIALIZERS).hexdigest(),
            "8fb0083e1b2e867372a5f3b7bfbe037d1903aa77ef09308ae7db47beab4cef3d",
        )
        self.assertEqual(
            core_build.CORE_STORES_SERIALIZERS_SHA256,
            "85c7f6dfc6a8ccfdd5aef35827d9d4aa5baa3b557d84caec53d56bffd01abb66",
        )
        rendered = core_build.render_core_dockerfile(
            UPSTREAM_DOCKERFILE,
            UPSTREAM_LICENSE,
            UPSTREAM_REGISTRY,
            UPSTREAM_STORES_BACKENDS,
            UPSTREAM_STORES_SERIALIZERS,
            operator_program='pass\n',
            request_limits_program='pass\n',
            request_limits_sha256='0' * 64,
            operator_module_sha256='a' * 64,
        )
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
        self.assertIn("test -f /zentral/zentral/core/stores/backends/all.py", rendered)
        self.assertIn("test -f /zentral/zentral/core/stores/serializers.py", rendered)
        self.assertIn("prepare_core_registry.py", rendered)
        self.assertIn("prepare_core_stores.py", rendered)
        self.assertIn("Core registry input SHA256", rendered)
        self.assertIn("Core stores backend registry input SHA256", rendered)
        self.assertIn("Core stores serializers input SHA256", rendered)

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

    def test_store_narrowing_removes_only_ee_backends(self) -> None:
        backends = core_build.narrow_core_store_backends(UPSTREAM_STORES_BACKENDS)
        serializers = core_build.narrow_core_store_serializers(UPSTREAM_STORES_SERIALIZERS)
        self.assertIn(b"Modified by azd-santa", backends)
        self.assertIn(b'ClickHouse = "CLICKHOUSE"', backends)
        self.assertIn(b'Elasticsearch = "ELASTICSEARCH"', backends)
        self.assertIn(b'HTTP = "HTTP"', backends)
        self.assertIn(b'Kinesis = "KINESIS"', backends)
        self.assertIn(b'OpenSearch = "OPENSEARCH"', backends)
        self.assertIn(b'S3Parquet = "S3_PARQUET"', backends)
        for unavailable in (b"Datadog", b"Panther", b"Snowflake", b"Splunk", b"SumoLogic"):
            self.assertNotIn(unavailable, backends)
        for unavailable in (b"datadog", b"panther", b"snowflake", b"splunk", b"sumo_logic"):
            self.assertNotIn(b"backends." + unavailable, serializers)
            self.assertNotIn(unavailable + b"_kwargs", serializers)
        self.assertIn(b"backends.clickhouse", serializers)
        self.assertIn(b"backends.es_os_base", serializers)
        self.assertIn(b"backends.http", serializers)
        self.assertIn(b"backends.kinesis", serializers)
        self.assertIn(b"backends.opensearch", serializers)
        self.assertIn(b"backends.s3_parquet", serializers)
        with self.assertRaises(ValueError):
            core_build.narrow_core_store_backends(UPSTREAM_STORES_BACKENDS + b"\n")
        with self.assertRaises(ValueError):
            core_build.narrow_core_store_serializers(UPSTREAM_STORES_SERIALIZERS + b"\n")

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
            (source / "zentral" / "core" / "stores" / "backends").mkdir(parents=True)
            (source / "ee").mkdir()
            (source / "server" / "realms" / "backends").mkdir(parents=True)
            (source / "Dockerfile").write_bytes(UPSTREAM_DOCKERFILE.encode("utf-8"))
            (source / "LICENSE").write_bytes(UPSTREAM_LICENSE)
            (source / core_build.REGISTRY_PATH).write_bytes(UPSTREAM_REGISTRY)
            (source / core_build.STORES_BACKENDS_PATH).write_bytes(UPSTREAM_STORES_BACKENDS)
            (source / core_build.STORES_SERIALIZERS_PATH).write_bytes(UPSTREAM_STORES_SERIALIZERS)
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


class SyncCredentialGuard(unittest.TestCase):
    def test_shared_guard_rejects_invalid_authority_before_processing_but_not_used_quota(self):
        method = ast.parse('def post(self):\n' + core_build.SYNC_GUARD + '        return True\n')
        class Denied(Exception):
            pass
        for revoked, expired, missing in ((False, False, False), (True, False, False),
                                          (False, True, False), (False, False, True)):
            secret = None if missing else SimpleNamespace(is_revoked=revoked, is_expired=expired, is_used_up=True)
            manager = mock.Mock()
            manager.filter.return_value.first.return_value = secret
            namespace = dict(EnrollmentSecret=SimpleNamespace(objects=manager), PermissionDenied=Denied)
            exec(compile(method, 'original-sync-guard', 'exec'), namespace)
            instance = SimpleNamespace(enrollment_secret_secret='synthetic')
            if revoked or expired or missing:
                with self.assertRaises(Denied):
                    namespace['post'](instance)
            else:
                self.assertTrue(namespace['post'](instance))
            manager.filter.assert_called_once_with(secret='synthetic')

    def test_unreviewed_sync_source_is_not_modified(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'public_views.py'
            path.write_bytes(b'unreviewed')
            program = core_build._sync_transform_script().replace('/zentral/' + core_build.SYNC_VIEW_PATH, path.as_posix())
            with self.assertRaisesRegex(RuntimeError, 'sync input hash mismatch'):
                exec(compile(program, 'sync-transform', 'exec'), {})
            self.assertEqual(path.read_bytes(), b'unreviewed')


if __name__ == "__main__":
    unittest.main()
