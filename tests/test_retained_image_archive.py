"""Synthetic bounded archive and identity checks."""
import hashlib
import io
import json
from pathlib import Path
import sys
import tarfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'experiments/server'))
from retained_image_archive import ArchiveRejected, verify_archive


def sha(data):
    return hashlib.sha256(data).hexdigest()


def fixture(*, arch='amd64', layer=True, multiple=False, tagged=False, oci=False, wrong_index=False,
            manifest_id=False, classic_sources=False, platform_index=None):
    layer_data = b'synthetic layer'
    diff_id = 'sha256:' + sha(layer_data)
    config = json.dumps(dict(os='linux', architecture=arch,
                            rootfs=dict(type='layers', diff_ids=[diff_id]))).encode()
    image_id = 'sha256:' + sha(config)
    dirname = 'blobs/sha256/' if oci else ''
    config_name = dirname + sha(config) + ('' if oci else '.json')
    layer_name = dirname + sha(layer_data) if oci else 'layer.tar'
    manifest = dict(Config=config_name, Layers=[layer_name], RepoTags=['synthetic:latest'] if tagged else None)
    oci_layer = {'digest': 'sha256:' + 'b' * 64 if classic_sources else diff_id}
    if classic_sources:
        manifest['LayerSources'] = {diff_id: oci_layer}
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        files = {'manifest.json': json.dumps([manifest] * (2 if multiple else 1)).encode(), config_name: config}
        if layer:
            files[layer_name] = layer_data
        if oci:
            oci_manifest = json.dumps(dict(schemaVersion=2,
                config={'digest': 'sha256:' + '0' * 64 if wrong_index else image_id},
                layers=[oci_layer])).encode()
            files[dirname + sha(oci_manifest)] = oci_manifest
            descriptor = dict(mediaType='application/vnd.oci.image.manifest.v1+json',
                              digest='sha256:' + sha(oci_manifest), size=len(oci_manifest))
            index_descriptors = [descriptor]
            if platform_index is not None:
                linux = dict(os='linux', architecture='amd64')
                candidate = dict(descriptor, platform=linux)
                other = dict(descriptor, digest='sha256:' + 'a' * 64,
                             platform=dict(os='linux', architecture='arm64', variant='v8'))
                attestation = dict(other, digest='sha256:' + 'c' * 64,
                                   platform=dict(os='unknown', architecture='unknown'))
                manifests = [other, candidate, attestation]
                if platform_index == 'ambiguous':
                    manifests.append(dict(other, platform=linux))
                elif platform_index == 'missing-platform':
                    del candidate['platform']
                elif platform_index == 'wrong-platform':
                    candidate['platform'] = dict(os='windows', architecture='amd64')
                elif platform_index == 'wrong-size':
                    candidate['size'] += 1
                elif platform_index == 'missing-manifest':
                    candidate['digest'] = 'sha256:' + 'd' * 64
                nested = json.dumps(dict(schemaVersion=2, manifests=manifests)).encode()
                descriptor = dict(mediaType='application/vnd.oci.image.index.v1+json',
                                  digest='sha256:' + sha(nested), size=len(nested))
                files[dirname + sha(nested)] = nested
                if platform_index == 'wrong-index-size':
                    descriptor['size'] += 1
                elif platform_index == 'changed-index':
                    files[dirname + sha(nested)] = nested + b' '
                index_descriptors = [descriptor]
                if platform_index == 'flattened':
                    # A single-platform save may retain the image and its attestation but drop the pinned index.
                    del files[dirname + sha(nested)]
                    index_descriptors = [candidate, attestation]
            files['index.json'] = json.dumps(dict(schemaVersion=2, manifests=index_descriptors)).encode()
            if manifest_id:
                image_id = descriptor['digest']
        for name, data in files.items():
            member = tarfile.TarInfo(name)
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
    return stream.getvalue(), image_id


class RetainedImageTests(unittest.TestCase):
    def verify(self, data, expected_id, **overrides):
        expectations = {'archive_sha256': sha(data), 'archive_bytes': len(data), 'image_id': expected_id}
        expectations.update(overrides)
        return verify_archive(io.BytesIO(data), **expectations)

    def test_binds_configuration_digest_and_platform(self):
        for options in ({}, {'oci': True}, {'oci': True, 'manifest_id': True},
                        {'oci': True, 'classic_sources': True}):
            data, image_id = fixture(**options)
            result = self.verify(data, image_id)
            self.assertEqual(result['image_id'], image_id)
            self.assertEqual(result['archive_sha256'], sha(data))
            self.assertEqual(result['platform'], 'linux/amd64')
            self.assertFalse(result['image_loaded'])

    def test_corruption_truncation_trailing_archive_wrong_id_and_limit(self):
        data, image_id = fixture()
        for case, overrides in ((data[:512] + b'x' + data[513:], {'archive_sha256': sha(data)}),
                                (data[:2048], {'archive_bytes': len(data)}),
                                (data + data, {}),
                                (data, {'maximum': len(data)-1}),
                                (data, {'image_id': 'sha256:' + '0' * 64})):
            with self.assertRaises(ArchiveRejected):
                self.verify(case, image_id, **overrides)

    def test_rejects_wrong_platform_missing_layer_extra_image_tag_and_oci_disagreement(self):
        for args in (dict(arch='arm64'), dict(layer=False), dict(multiple=True), dict(tagged=True),
                     dict(oci=True, wrong_index=True)):
            with self.subTest(args=args), self.assertRaises(ArchiveRejected):
                self.verify(*fixture(**args))

    def test_pinned_platform_index_selects_only_linux_amd64(self):
        data, image_id = fixture(oci=True, manifest_id=True, platform_index='valid')
        result = self.verify(data, image_id)
        self.assertNotEqual(result['config_id'], image_id)
        self.assertEqual(result['image_id'], image_id)
        self.assertEqual(result['platform'], 'linux/amd64')

    def test_rejects_inconsistent_or_ambiguous_platform_index(self):
        for mode in ('ambiguous', 'missing-platform', 'wrong-platform', 'wrong-size',
                     'wrong-index-size', 'missing-manifest', 'changed-index', 'flattened'):
            with self.subTest(mode=mode), self.assertRaises(ArchiveRejected):
                self.verify(*fixture(oci=True, manifest_id=True, platform_index=mode))

    def test_deadline_is_failure(self):
        with patch('retained_image_archive.time.monotonic', side_effect=[0, 1000]):
            with self.assertRaises(ArchiveRejected):
                self.verify(*fixture())
