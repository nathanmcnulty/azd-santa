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


def render_core_dockerfile(
    upstream_dockerfile: str,
    upstream_license: bytes,
    upstream_registry: bytes,
    *,
    license_sha256: str = UPSTREAM_LICENSE_SHA256,
    registry_sha256: str = UPSTREAM_REGISTRY_SHA256,
) -> str:
    """Render the reviewed Dockerfile shape with only the core runtime stage."""

    if "COPY ./ee /zentral/ee" not in upstream_dockerfile:
        raise ValueError("upstream Dockerfile no longer has the reviewed EE copy boundary")
    registry_transform_b64 = base64.b64encode(
        _registry_transform_script(upstream_registry, registry_sha256).encode("utf-8")
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
    rendered = _replace_once(
        rendered,
        "RUN printf \"version = \\\"\\\"\\\"$APP_VERSION\\\"\\\"\\\"\\n\" > /zentral/server/base/deployment.py\n",
        "RUN printf \"version = \\\"\\\"\\\"$APP_VERSION\\\"\\\"\\\"\\n\" > /zentral/server/base/deployment.py\n"
        "RUN test ! -e /zentral/ee \\\n"
        "    && test -d /zentral/server/accounts \\\n"
        "    && test -d /zentral/server/realms \\\n"
        "    && test -d /zentral/zentral/contrib/santa \\\n"
        "    && printf '%s\\n' \\\n"
        "        'UNOFFICIAL CORE-ONLY DERIVED BUILD' \\\n"
        f"        'Zentral source commit: {UPSTREAM_COMMIT}' \\\n"
        f"        'Zentral source: {UPSTREAM_SOURCE_URL}' \\\n"
        f"        'Upstream Dockerfile SHA256: {UPSTREAM_DOCKERFILE_SHA256}' \\\n"
        f"        'Upstream LICENSE SHA256: {UPSTREAM_LICENSE_SHA256}' \\\n"
        f"        'Core registry input SHA256: {registry_sha256}' \\\n"
        f"        'Core registry output SHA256: {CORE_REGISTRY_SHA256}' \\\n"
        "        'The upstream ee tree is intentionally omitted; no EE functionality is included.' \\\n"
        "        'The core registry was narrowed to LDAP; EE OIDC and SAML backends are unavailable.' \\\n"
        "        'The only source transformation is the reviewed core registry narrowing; review licensing before production use.' \\\n"
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
    return rendered


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
    )
    try:
        output_path.relative_to(source_root)
    except ValueError as exc:
        raise ValueError("output must be an absent path inside the upstream build context") from exc

    output_path.parent.mkdir(parents=True, exist_ok=True)
    rendered = render_core_dockerfile(
        (source_root / "Dockerfile").read_text(encoding="utf-8"),
        (source_root / "LICENSE").read_bytes(),
        (source_root / REGISTRY_PATH).read_bytes(),
        license_sha256=UPSTREAM_LICENSE_SHA256,
        registry_sha256=UPSTREAM_REGISTRY_SHA256,
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
