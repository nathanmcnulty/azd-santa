"""Derive a core-only Zentral Dockerfile without changing the source checkout.

This tool is intentionally narrow: it verifies the reviewed Zentral source
identity, renders a deterministic Dockerfile beside that source, and copies
only Apache/core files in the final image.  It does not remove or rewrite the
upstream ``ee`` tree and does not implement a license gate.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import subprocess
from pathlib import Path


UPSTREAM_COMMIT = "88e67b3ce49033aab028029937a6e14f7c489073"
UPSTREAM_SOURCE_URL = (
    "https://github.com/zentralopensource/zentral/tree/"
    f"{UPSTREAM_COMMIT}"
)
UPSTREAM_DOCKERFILE_SHA256 = "dd06e76e0b325684c0c07734cfb1b951218678fb454b8af18e719f309c2e94e1"
UPSTREAM_LICENSE_SHA256 = "00f43b4775da6dcbe63d20b3b2c36e616f35af5595d02c590278e75d9d86793c"
UPSTREAM_REGISTRY_SHA256 = "d216a4a58acb8258794bd67db64dec5f6a69ebfe8d93d5ebbe1b702e88704cca"
CORE_REGISTRY_SHA256 = "2c2aceac8fb47a73a418b471a87e0a47e2c852a7f57e7022e27f400aa79b261f"
REGISTRY_PATH = "server/realms/backends/registry.py"
SYNC_VIEW_PATH = "zentral/contrib/santa/public_views.py"
UPSTREAM_SYNC_VIEW_SHA256 = "95e0a59e6f37b5a3f43cb0db4c457981163734d954e1cc5b68df82826d412d97"
CORE_SYNC_VIEW_SHA256 = "f6041b2e83350dad583bb3a26265a182dab0d674f8a096f5c522783d8093e33d"
SYNC_GUARD = '''        # azd-santa: continuing sync authority excludes enrollment quota.
        sync_secret = EnrollmentSecret.objects.filter(secret=self.enrollment_secret_secret).first()
        if sync_secret is None or sync_secret.is_revoked or sync_secret.is_expired:
            raise PermissionDenied("Invalid sync credential")

'''
UPSTREAM_STORES_BACKENDS_SHA256 = "7db6c71eb508bce42d92803c9dc83799fd7d5dbacec577a47f98aaf06b0a5d4a"
CORE_STORES_BACKENDS_SHA256 = "3a61216f59b69808a926e7063737004fc0b60d4e8642427f22323eca61a7a09b"
STORES_BACKENDS_PATH = "zentral/core/stores/backends/all.py"
UPSTREAM_STORES_SERIALIZERS_SHA256 = "8fb0083e1b2e867372a5f3b7bfbe037d1903aa77ef09308ae7db47beab4cef3d"
CORE_STORES_SERIALIZERS_SHA256 = "85c7f6dfc6a8ccfdd5aef35827d9d4aa5baa3b557d84caec53d56bffd01abb66"
STORES_SERIALIZERS_PATH = "zentral/core/stores/serializers.py"

# Apache-2.0 upstream snapshot at the pin above; see THIRD_PARTY_NOTICES.md.
UPSTREAM_REGISTRY = b"""from realms.backends.ldap import LDAPRealmBackend
from realms.backends.openidc import OpenIDConnectRealmBackend
from realms.backends.saml import SAMLRealmBackend


backend_classes = {
    "ldap": LDAPRealmBackend,
    "openidc": OpenIDConnectRealmBackend,
    "saml": SAMLRealmBackend,
}
"""
CORE_REGISTRY_NARROWED = b"""# Modified by azd-santa: optional enterprise OIDC/SAML backends omitted; core LDAP retained.
from realms.backends.ldap import LDAPRealmBackend


backend_classes = {
    "ldap": LDAPRealmBackend,
}
"""

STORES_BACKENDS_REMOVED_LINES = (
    b'    Datadog = "DATADOG", "Datadog"\n',
    b'    Panther = "PANTHER", "Panther"\n',
    b'    Snowflake = "SNOWFLAKE", "Snowflake"\n',
    b'    Splunk = "SPLUNK", "Splunk"\n',
    b'    SumoLogic = "SUMO_LOGIC", "Sumo Logic"\n',
)
STORES_SERIALIZERS_REMOVED_LINES = (
    b"from zentral.core.stores.backends.datadog import DatadogStoreSerializer\n",
    b"from zentral.core.stores.backends.panther import PantherStoreSerializer\n",
    b"from zentral.core.stores.backends.snowflake import SnowflakeStoreSerializer\n",
    b"from zentral.core.stores.backends.splunk import SplunkStoreSerializer\n",
    b"from zentral.core.stores.backends.sumo_logic import SumoLogicStoreSerializer\n",
    b'    datadog_kwargs = DatadogStoreSerializer(source="get_datadog_kwargs", required=False, allow_null=True)\n',
    b'    panther_kwargs = PantherStoreSerializer(source="get_panther_kwargs", required=False, allow_null=True)\n',
    b'    snowflake_kwargs = SnowflakeStoreSerializer(source="get_snowflake_kwargs", required=False, allow_null=True)\n',
    b'    splunk_kwargs = SplunkStoreSerializer(source="get_splunk_kwargs", required=False, allow_null=True)\n',
    b'    sumo_logic_kwargs = SumoLogicStoreSerializer(source="get_sumo_logic_kwargs", required=False, allow_null=True)\n',
    b'            "datadog_kwargs",\n',
    b'            "panther_kwargs",\n',
    b'            "snowflake_kwargs",\n',
    b'            "splunk_kwargs",\n',
    b'            "sumo_logic_kwargs",\n',
)
STORES_BACKENDS_NOTICE = b"# Modified by azd-santa: optional enterprise store backends omitted; core backends retained.\n"
STORES_SERIALIZERS_NOTICE = b"# Modified by azd-santa: optional enterprise store backends and serializer fields omitted; core backends retained.\n"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def narrow_core_registry(registry_bytes: bytes, *, expected_sha256: str = UPSTREAM_REGISTRY_SHA256) -> bytes:
    """Remove only the EE registry entries from the reviewed core registry."""

    actual_sha256 = hashlib.sha256(registry_bytes).hexdigest()
    if actual_sha256 != expected_sha256.lower() or registry_bytes != UPSTREAM_REGISTRY:
        raise ValueError(
            "unexpected core registry input: "
            f"expected {expected_sha256}, got {actual_sha256}"
        )
    if hashlib.sha256(CORE_REGISTRY_NARROWED).hexdigest() != CORE_REGISTRY_SHA256:
        raise ValueError("internal narrowed registry hash does not match its reviewed value")
    return CORE_REGISTRY_NARROWED


def narrow_core_store_file(
    file_bytes: bytes,
    *,
    expected_sha256: str,
    output_sha256: str,
    removed_lines: tuple[bytes, ...],
    notice: bytes,
    label: str,
) -> bytes:
    """Remove only reviewed EE store lines from one exact upstream core file."""

    actual_sha256 = hashlib.sha256(file_bytes).hexdigest()
    if actual_sha256 != expected_sha256.lower():
        raise ValueError(
            f"unexpected {label} input: expected {expected_sha256}, got {actual_sha256}"
        )
    narrowed = file_bytes
    for line in removed_lines:
        if narrowed.count(line) != 1:
            raise ValueError(f"unexpected {label} shape; expected one reviewed line")
        narrowed = narrowed.replace(line, b"", 1)
    narrowed = notice + narrowed
    actual_output_sha256 = hashlib.sha256(narrowed).hexdigest()
    if actual_output_sha256 != output_sha256.lower():
        raise ValueError(
            f"internal narrowed {label} hash mismatch: "
            f"expected {output_sha256}, got {actual_output_sha256}"
        )
    return narrowed


def narrow_core_store_backends(file_bytes: bytes, *, expected_sha256: str = UPSTREAM_STORES_BACKENDS_SHA256) -> bytes:
    return narrow_core_store_file(
        file_bytes,
        expected_sha256=expected_sha256,
        output_sha256=CORE_STORES_BACKENDS_SHA256,
        removed_lines=STORES_BACKENDS_REMOVED_LINES,
        notice=STORES_BACKENDS_NOTICE,
        label="core store backend registry",
    )


def narrow_core_store_serializers(
    file_bytes: bytes,
    *,
    expected_sha256: str = UPSTREAM_STORES_SERIALIZERS_SHA256,
) -> bytes:
    return narrow_core_store_file(
        file_bytes,
        expected_sha256=expected_sha256,
        output_sha256=CORE_STORES_SERIALIZERS_SHA256,
        removed_lines=STORES_SERIALIZERS_REMOVED_LINES,
        notice=STORES_SERIALIZERS_NOTICE,
        label="core store serializers",
    )


def _git_head(source_root: Path) -> str:
    try:
        completed = subprocess.run(
            ["git", "-C", str(source_root), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise ValueError("source must be a Git checkout with a readable HEAD") from exc
    return completed.stdout.strip().lower()


def _git_status(source_root: Path) -> str:
    try:
        completed = subprocess.run(
            ["git", "-C", str(source_root), "status", "--porcelain", "--untracked-files=all"],
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise ValueError("source must have a readable Git worktree status") from exc
    return completed.stdout


def validate_source(
    source_root: Path,
    *,
    expected_commit: str = UPSTREAM_COMMIT,
    expected_dockerfile_sha256: str = UPSTREAM_DOCKERFILE_SHA256,
    expected_license_sha256: str = UPSTREAM_LICENSE_SHA256,
    expected_registry_sha256: str = UPSTREAM_REGISTRY_SHA256,
    expected_stores_backends_sha256: str = UPSTREAM_STORES_BACKENDS_SHA256,
    expected_stores_serializers_sha256: str = UPSTREAM_STORES_SERIALIZERS_SHA256,
) -> None:
    """Fail closed unless *source_root* is the reviewed upstream checkout."""

    source_root = source_root.resolve()
    if not source_root.is_dir():
        raise ValueError(f"source directory does not exist: {source_root}")

    required = (
        source_root / "Dockerfile",
        source_root / "LICENSE",
        source_root / "server",
        source_root / "zentral",
        source_root / "ee",
        source_root / REGISTRY_PATH,
        source_root / STORES_BACKENDS_PATH,
        source_root / STORES_SERIALIZERS_PATH,
    )
    missing = [str(path.relative_to(source_root)) for path in required if not path.exists()]
    if missing:
        raise ValueError(f"source is missing expected upstream paths: {', '.join(missing)}")

    if (source_root / ".git").exists():
        actual_commit = _git_head(source_root)
        if actual_commit != expected_commit.lower():
            raise ValueError(
                f"unexpected Zentral source commit: expected {expected_commit}, got {actual_commit}"
            )
        if status := _git_status(source_root):
            raise ValueError(f"source checkout is not clean:\n{status.rstrip()}")
    elif source_root.name != f"zentral-{expected_commit.lower()}":
        raise ValueError(
            "source is not a Git checkout; expected the exact archive directory "
            f"zentral-{expected_commit.lower()}"
        )

    actual_dockerfile_sha256 = _sha256(source_root / "Dockerfile")
    if actual_dockerfile_sha256 != expected_dockerfile_sha256.lower():
        raise ValueError(
            "unexpected upstream Dockerfile SHA256: "
            f"expected {expected_dockerfile_sha256}, got {actual_dockerfile_sha256}"
        )

    actual_license_sha256 = _sha256(source_root / "LICENSE")
    if actual_license_sha256 != expected_license_sha256.lower():
        raise ValueError(
            "unexpected upstream LICENSE SHA256: "
            f"expected {expected_license_sha256}, got {actual_license_sha256}"
        )

    actual_registry_sha256 = _sha256(source_root / REGISTRY_PATH)
    if actual_registry_sha256 != expected_registry_sha256.lower():
        raise ValueError(
            "unexpected core registry SHA256: "
            f"expected {expected_registry_sha256}, got {actual_registry_sha256}"
        )

    actual_stores_backends_sha256 = _sha256(source_root / STORES_BACKENDS_PATH)
    if actual_stores_backends_sha256 != expected_stores_backends_sha256.lower():
        raise ValueError(
            "unexpected core store backend registry SHA256: "
            f"expected {expected_stores_backends_sha256}, got {actual_stores_backends_sha256}"
        )

    actual_stores_serializers_sha256 = _sha256(source_root / STORES_SERIALIZERS_PATH)
    if actual_stores_serializers_sha256 != expected_stores_serializers_sha256.lower():
        raise ValueError(
            "unexpected core store serializers SHA256: "
            f"expected {expected_stores_serializers_sha256}, got {actual_stores_serializers_sha256}"
        )


def _replace_once(text: str, old: str, new: str, label: str) -> str:
    if text.count(old) != 1:
        raise ValueError(f"upstream Dockerfile shape changed; expected one {label}")
    return text.replace(old, new, 1)


def _registry_transform_script(registry_bytes: bytes, expected_sha256: str) -> str:
    narrowed = narrow_core_registry(registry_bytes, expected_sha256=expected_sha256)
    source_b64 = base64.b64encode(registry_bytes).decode("ascii")
    narrowed_b64 = base64.b64encode(narrowed).decode("ascii")
    return (
        "from base64 import b64decode\n"
        "from hashlib import sha256\n"
        "from pathlib import Path\n"
        "path = Path('/zentral/server/realms/backends/registry.py')\n"
        f"expected = b64decode('{source_b64}')\n"
        f"narrowed = b64decode('{narrowed_b64}')\n"
        "actual = path.read_bytes()\n"
        f"if sha256(actual).hexdigest() != '{expected_sha256}': raise RuntimeError('core registry input hash mismatch')\n"
        "if actual != expected: raise RuntimeError('core registry input bytes mismatch')\n"
        "path.write_bytes(narrowed)\n"
        f"if sha256(path.read_bytes()).hexdigest() != '{CORE_REGISTRY_SHA256}': raise RuntimeError('core registry output hash mismatch')\n"
    )


def _store_transform_script(
    stores_backends_bytes: bytes,
    stores_serializers_bytes: bytes,
    *,
    stores_backends_sha256: str,
    stores_serializers_sha256: str,
) -> str:
    backends = narrow_core_store_backends(stores_backends_bytes, expected_sha256=stores_backends_sha256)
    serializers = narrow_core_store_serializers(
        stores_serializers_bytes,
        expected_sha256=stores_serializers_sha256,
    )
    removed_lines_b64 = lambda lines: "[" + ", ".join(
        f"b64decode('{base64.b64encode(line).decode('ascii')}')" for line in lines
    ) + "]"
    return (
        "from base64 import b64decode\n"
        "from hashlib import sha256\n"
        "from pathlib import Path\n"
        "def narrow(path, expected_sha256, output_sha256, removed_lines, notice):\n"
        "    actual = path.read_bytes()\n"
        "    if sha256(actual).hexdigest() != expected_sha256: raise RuntimeError(f'{path} input hash mismatch')\n"
        "    narrowed = actual\n"
        "    for line in removed_lines:\n"
        "        if narrowed.count(line) != 1: raise RuntimeError(f'{path} input shape mismatch')\n"
        "        narrowed = narrowed.replace(line, b'', 1)\n"
        "    narrowed = notice + narrowed\n"
        "    if sha256(narrowed).hexdigest() != output_sha256: raise RuntimeError(f'{path} output hash mismatch')\n"
        "    path.write_bytes(narrowed)\n"
        "narrow(\n"
        f"    Path('/zentral/{STORES_BACKENDS_PATH}'),\n"
        f"    '{stores_backends_sha256}',\n"
        f"    '{CORE_STORES_BACKENDS_SHA256}',\n"
        f"    {removed_lines_b64(STORES_BACKENDS_REMOVED_LINES)},\n"
        f"    b64decode('{base64.b64encode(STORES_BACKENDS_NOTICE).decode('ascii')}'),\n"
        ")\n"
        "narrow(\n"
        f"    Path('/zentral/{STORES_SERIALIZERS_PATH}'),\n"
        f"    '{stores_serializers_sha256}',\n"
        f"    '{CORE_STORES_SERIALIZERS_SHA256}',\n"
        f"    {removed_lines_b64(STORES_SERIALIZERS_REMOVED_LINES)},\n"
        f"    b64decode('{base64.b64encode(STORES_SERIALIZERS_NOTICE).decode('ascii')}'),\n"
        ")\n"
    )


def _sync_transform_script(input_sha256=UPSTREAM_SYNC_VIEW_SHA256,
                           output_sha256=CORE_SYNC_VIEW_SHA256) -> str:
    """Apply the original continuing-authority guard to one exact core source."""
    return (
        "from pathlib import Path\nfrom hashlib import sha256\n"
        f"path=Path('/zentral/{SYNC_VIEW_PATH}')\n"
        "source=path.read_bytes()\n"
        f"if sha256(source).hexdigest()!={input_sha256!r}: raise RuntimeError('sync input hash mismatch')\n"
        "old=b'from zentral.contrib.inventory.models import PrincipalUserSource'\n"
        "new=b'from zentral.contrib.inventory.models import EnrollmentSecret, PrincipalUserSource'\n"
        "anchor=b'        self.client_cert_dn = self._get_client_cert_dn()'\n"
        "if source.count(old)!=1 or source.count(anchor)!=1: raise RuntimeError('sync source shape mismatch')\n"
        f"guard={SYNC_GUARD.encode()!r}\n"
        "result=source.replace(old,new,1).replace(anchor,guard+anchor,1)\n"
        "result=b'# Modified by azd-santa: enforce revocation and expiry for continuing sync credentials.\\n'+result\n"
        f"if sha256(result).hexdigest()!={output_sha256!r}: raise RuntimeError('sync output hash mismatch')\n"
        "compile(result, str(path), 'exec')\npath.write_bytes(result)\n"
    )


def render_core_dockerfile(
    upstream_dockerfile: str,
    upstream_license: bytes,
    upstream_registry: bytes,
    upstream_stores_backends: bytes,
    upstream_stores_serializers: bytes,
    *,
    operator_program: str,
    operator_module_sha256: str,
    license_sha256: str = UPSTREAM_LICENSE_SHA256,
    registry_sha256: str = UPSTREAM_REGISTRY_SHA256,
    stores_backends_sha256: str = UPSTREAM_STORES_BACKENDS_SHA256,
    stores_serializers_sha256: str = UPSTREAM_STORES_SERIALIZERS_SHA256,
) -> str:
    """Render the reviewed Dockerfile shape with only the core runtime stage."""

    if "COPY ./ee /zentral/ee" not in upstream_dockerfile:
        raise ValueError("upstream Dockerfile no longer has the reviewed EE copy boundary")
    registry_transform_b64 = base64.b64encode(
        _registry_transform_script(upstream_registry, registry_sha256).encode("utf-8")
    ).decode("ascii")
    stores_transform_b64 = base64.b64encode(
        _store_transform_script(
            upstream_stores_backends,
            upstream_stores_serializers,
            stores_backends_sha256=stores_backends_sha256,
            stores_serializers_sha256=stores_serializers_sha256,
        ).encode("utf-8")
    ).decode("ascii")

    rendered = _replace_once(
        upstream_dockerfile,
        "ARG APP_ENV=dev",
        "ARG APP_ENV=core",
        "default APP_ENV",
    )

    stage1_start = "####\n# Build stage 1:\n"
    stage2_start = "#####\n# Build stage 2:\n"
    if rendered.count(stage1_start) != 1 or rendered.count(stage2_start) != 1:
        raise ValueError("upstream Dockerfile stage boundaries changed")
    stage1_prefix, stage1_rest = rendered.split(stage1_start, 1)
    _, stage2_suffix = stage1_rest.split(stage2_start, 1)
    rendered = (
        stage1_prefix
        + "####\n"
        "# Build stage 1:\n"
        "# - reuse the common Apache/core dependencies only\n"
        "#\n"
        "FROM base-builder AS core-builder\n\n\n"
        + stage2_start
        + stage2_suffix
    )

    stage3_start = "####\n# Build stage 3:\n"
    stage4_start = "####\n# Build stage 4:\n"
    if rendered.count(stage3_start) != 1 or rendered.count(stage4_start) != 1:
        raise ValueError("upstream Dockerfile runtime stage boundaries changed")
    stage3_prefix, stage3_rest = rendered.split(stage3_start, 1)
    _, stage4_suffix = stage3_rest.split(stage4_start, 1)
    rendered = (
        stage3_prefix
        + "####\n"
        "# Build stage 3:\n"
        "# - install the common core virtualenv only\n"
        "#\n"
        "FROM base-runner AS core-runner\n"
        "COPY --from=core-builder /opt/venv /opt/venv\n\n\n"
        + stage4_start
        + stage4_suffix
    )

    rendered = _replace_once(
        rendered,
        "COPY ./ee /zentral/ee\n",
        "",
        "EE copy",
    )
    license_b64 = base64.b64encode(upstream_license).decode("ascii")
    license_chunks = [license_b64[index:index + 76] for index in range(0, len(license_b64), 76)]
    if not license_chunks:
        raise ValueError("upstream LICENSE must not be empty")
    license_install = (
        "RUN mkdir -p /usr/share/doc/zentral \\\n"
        "    && printf '%s' \\\n"
        + "".join(f"        '{chunk}' \\\n" for chunk in license_chunks)
        + "        | base64 -d > /usr/share/doc/zentral/LICENSE \\\n"
        f"    && printf '%s  %s\\n' '{license_sha256}' '/usr/share/doc/zentral/LICENSE' | sha256sum -c -\n"
    )
    rendered = _replace_once(
        rendered,
        "COPY docker-entrypoint.py /zentral/\n",
        "COPY docker-entrypoint.py /zentral/\n" + license_install,
        "documentation copy anchor",
    )
    registry_transform = (
        "RUN printf '%s' '" + registry_transform_b64 + "' | base64 -d > /tmp/prepare_core_registry.py \\\n"
        "    && python /tmp/prepare_core_registry.py \\\n"
        "    && rm /tmp/prepare_core_registry.py\n"
    )
    rendered = _replace_once(
        rendered,
        "COPY ./server /zentral/server\n",
        "COPY ./server /zentral/server\n" + registry_transform,
        "core registry transform anchor",
    )
    stores_transform = (
        "RUN printf '%s' '" + stores_transform_b64 + "' | base64 -d > /tmp/prepare_core_stores.py \\\n"
        "    && python /tmp/prepare_core_stores.py \\\n"
        "    && rm /tmp/prepare_core_stores.py\n"
    )
    sync_transform_b64 = base64.b64encode(_sync_transform_script().encode()).decode('ascii')
    stores_transform += (
        "RUN printf '%s' '" + sync_transform_b64 + "' | base64 -d > /tmp/prepare_sync_guard.py \\\n"
        "    && python /tmp/prepare_sync_guard.py \\\n"
        "    && rm /tmp/prepare_sync_guard.py\n"
    )
    operator_b64 = base64.b64encode(operator_program.encode('utf-8')).decode('ascii')
    stores_transform += (
        "RUN printf '%s' '" + operator_b64 + "' | base64 -d > /tmp/prepare_operator_mfa.py \\\n"
        "    && python /tmp/prepare_operator_mfa.py \\\n"
        "    && rm /tmp/prepare_operator_mfa.py\n"
    )
    rendered = _replace_once(
        rendered,
        "COPY ./zentral /zentral/zentral\n",
        "COPY ./zentral /zentral/zentral\n" + stores_transform,
        "core stores transform anchor",
    )
    rendered = _replace_once(
        rendered,
        "RUN printf \"version = \\\"\\\"\\\"$APP_VERSION\\\"\\\"\\\"\\n\" > /zentral/server/base/deployment.py\n",
        "RUN printf \"version = \\\"\\\"\\\"$APP_VERSION\\\"\\\"\\\"\\n\" > /zentral/server/base/deployment.py\n"
        "RUN test ! -e /zentral/ee \\\n"
        "    && test -d /zentral/server/accounts \\\n"
        "    && test -d /zentral/server/realms \\\n"
        "    && test -d /zentral/zentral/contrib/santa \\\n"
        "    && test -f /zentral/zentral/core/stores/backends/all.py \\\n"
        "    && test -f /zentral/zentral/core/stores/serializers.py \\\n"
        "    && printf '%s\\n' \\\n"
        "        'UNOFFICIAL CORE-ONLY DERIVED BUILD' \\\n"
        f"        'Zentral source commit: {UPSTREAM_COMMIT}' \\\n"
        f"        'Zentral source: {UPSTREAM_SOURCE_URL}' \\\n"
        f"        'Upstream Dockerfile SHA256: {UPSTREAM_DOCKERFILE_SHA256}' \\\n"
        f"        'Upstream LICENSE SHA256: {UPSTREAM_LICENSE_SHA256}' \\\n"
        f"        'Core registry input SHA256: {registry_sha256}' \\\n"
        f"        'Core registry output SHA256: {CORE_REGISTRY_SHA256}' \\\n"
        f"        'Core stores backend registry input SHA256: {stores_backends_sha256}' \\\n"
        f"        'Core stores backend registry output SHA256: {CORE_STORES_BACKENDS_SHA256}' \\\n"
        f"        'Core stores serializers input SHA256: {stores_serializers_sha256}' \\\n"
        f"        'Core stores serializers output SHA256: {CORE_STORES_SERIALIZERS_SHA256}' \\\n"
        "        'The upstream ee tree is intentionally omitted; no EE functionality is included.' \\\n"
        "        'The core registry was narrowed to LDAP; EE OIDC and SAML backends are unavailable.' \\\n"
        "        'Core store registry and serializer files were narrowed to Apache/core backends; EE store backends are unavailable.' \\\n"
        f"        'Santa sync view input SHA256: {UPSTREAM_SYNC_VIEW_SHA256}' \\\n"
        f"        'Santa sync view output SHA256: {CORE_SYNC_VIEW_SHA256}' \\\n"
        f"        'Original operator MFA module SHA256: {operator_module_sha256}' \\\n"
        "        'Core authentication/settings/forms integrate mandatory local operator MFA; human API tokens are denied.' \\\n"
        "        'An original sync credential guard enforces revocation/expiry without charging enrollment quota.' \\\n"
        "        'Source transformations are the reviewed registry/store narrowings and sync credential guard; review licensing before production use.' \\\n"
        "        > /usr/share/doc/zentral/CORE_BUILD_NOTICE.txt\n",
        "runtime assertion and build notice anchor",
    )

    if "FROM ${APP_ENV}-runner AS final" not in rendered:
        raise ValueError("upstream Dockerfile final stage changed")
    if "FROM dev-builder" in rendered or "FROM aws-builder" in rendered or "FROM gcp-builder" in rendered:
        raise ValueError("derived Dockerfile unexpectedly retains non-core builders")
    if "COPY ./ee" in rendered:
        raise ValueError("derived Dockerfile retains an EE copy or runtime path")
    if "FROM base-builder AS core-builder" not in rendered:
        raise ValueError("derived Dockerfile lacks core-builder")
    if "FROM base-runner AS core-runner" not in rendered:
        raise ValueError("derived Dockerfile lacks core-runner")
    if "COPY ./server /zentral/server\nRUN printf '%s' '" not in rendered:
        raise ValueError("derived Dockerfile lacks the core registry transform")
    if "COPY ./zentral /zentral/zentral\nRUN printf '%s' '" not in rendered:
        raise ValueError("derived Dockerfile lacks the core stores transform")
    rendered += (
        "\n# azd-santa: test actual non-root access, not only root path existence.\n"
        "RUN python -c \"from pathlib import Path; "
        "[Path(p).read_bytes() for p in "
        "('/zentral/server/server/settings.py', "
        "'/zentral/server/realms/backends/registry.py', "
        "'/zentral/server/azd_santa_operator.py', "
        "'/zentral/zentral/contrib/santa/public_views.py')]\"\n"
    )
    return rendered


def _operator_layer(source_root):
    helper = Path(__file__).with_name('prepare_operator_mfa.py')
    spec = importlib.util.spec_from_file_location('prepare_operator_mfa', helper)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.docker_program(source_root, Path(__file__).with_name('operator_mfa.py'))


def derive_core_dockerfile(source_root: Path, output_path: Path) -> Path:
    """Validate *source_root* and create a new Dockerfile at an absent path."""

    source_root = source_root.resolve()
    output_path = output_path.resolve()
    if output_path.exists() or output_path.is_symlink():
        raise FileExistsError(f"refusing to overwrite existing output: {output_path}")
    validate_source(
        source_root,
        expected_commit=UPSTREAM_COMMIT,
        expected_dockerfile_sha256=UPSTREAM_DOCKERFILE_SHA256,
        expected_license_sha256=UPSTREAM_LICENSE_SHA256,
        expected_registry_sha256=UPSTREAM_REGISTRY_SHA256,
        expected_stores_backends_sha256=UPSTREAM_STORES_BACKENDS_SHA256,
        expected_stores_serializers_sha256=UPSTREAM_STORES_SERIALIZERS_SHA256,
    )
    try:
        output_path.relative_to(source_root)
    except ValueError as exc:
        raise ValueError("output must be an absent path inside the upstream build context") from exc

    output_path.parent.mkdir(parents=True, exist_ok=True)
    operator_program, operator_sha = _operator_layer(source_root)
    rendered = render_core_dockerfile(
        (source_root / "Dockerfile").read_text(encoding="utf-8"),
        (source_root / "LICENSE").read_bytes(),
        (source_root / REGISTRY_PATH).read_bytes(),
        (source_root / STORES_BACKENDS_PATH).read_bytes(),
        (source_root / STORES_SERIALIZERS_PATH).read_bytes(),
        operator_program=operator_program,
        operator_module_sha256=operator_sha,
        license_sha256=UPSTREAM_LICENSE_SHA256,
        registry_sha256=UPSTREAM_REGISTRY_SHA256,
        stores_backends_sha256=UPSTREAM_STORES_BACKENDS_SHA256,
        stores_serializers_sha256=UPSTREAM_STORES_SERIALIZERS_SHA256,
    )
    with output_path.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(rendered)
    return output_path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path, help="exact upstream Zentral checkout")
    parser.add_argument("--output", required=True, type=Path, help="absent Dockerfile path inside source")
    args = parser.parse_args()
    output = derive_core_dockerfile(args.source, args.output)
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
