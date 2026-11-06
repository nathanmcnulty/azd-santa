"""Validate an explicit private runtime binding before any resume mutation."""
import argparse
import json
from pathlib import Path
import re

from test_live_zentral import load_fixture, validate_compose


def validate_selection(compose, fixture, expected_image):
    if not re.fullmatch(r'sha256:[0-9a-f]{64}', expected_image):
        raise ValueError('An immutable expected application image is required')
    compose, digest = validate_compose(compose)
    fixture = Path(fixture).resolve(strict=True)
    if fixture.parent != compose.parent:
        raise ValueError('Runtime and fixture must share the private directory')
    load_fixture(fixture, digest)
    services = json.loads(compose.read_text())['services']
    if any(services[name]['image'] != expected_image for name in ('web', 'workers', 'celery')):
        raise ValueError('Selected runtime image differs from the explicit expected image')
    return compose, digest


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compose', required=True)
    parser.add_argument('--fixture', required=True)
    parser.add_argument('--image', required=True)
    args = parser.parse_args()
    compose, digest = validate_selection(args.compose, args.fixture, args.image)
    if compose.parent != Path('/var/lib/azd-santa-qualification/runtime-fixed'):
        raise ValueError('Only the dedicated private qualification runtime is supported')
    print('SANTA_EXPLICIT_RUNTIME_BINDING_OK ' + digest)
