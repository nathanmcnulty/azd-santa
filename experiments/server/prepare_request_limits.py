"""Hash-bound integration of original request limits into pinned Apache/core.

Original integration tooling under the Unlicense. Preserve upstream license and
the continuing-credential guard; append a modification notice to the core file.
"""
import ast
import base64
import hashlib
from pathlib import Path

SOURCE = 'zentral/contrib/santa/public_views.py'
UPSTREAM_SHA256 = '95e0a59e6f37b5a3f43cb0db4c457981163734d954e1cc5b68df82826d412d97'
INPUT_SHA256 = 'f6041b2e83350dad583bb3a26265a182dab0d674f8a096f5c522783d8093e33d'
OUTPUT_SHA256 = '205315d6cf592fe53efaebb58fb6843c4f17f842d85b7c74816964385df1ec6a'
NOTICE = '# Modified by azd-santa: bound Santa request reads, decoding, nesting and event batches.\n'
OLD = '''    def _get_json_data(self, request):
        payload = request.body
        try:
            if request.META.get('HTTP_CONTENT_ENCODING', None) in ("zlib", "deflate"):
                payload = zlib.decompress(payload)
            data = json.loads(payload)
        except ValueError:
            data = None
        # every stage reads the payload as a mapping, and santa always sends one. An empty body,
        # or a JSON value that is not an object, is a broken client, not a stage without a request
        if not isinstance(data, dict):
            logger.error("Machine %s: could not read a JSON object from the request body",
                         self.hardware_uuid)
            raise SuspiciousOperation("Could not read JSON data")
        return data
'''
PATCHES = (
    ('from django.views.generic import View',
     'from django.views.generic import View\nfrom azd_santa_request_limits import decode_request, RequestRejected'),
    (OLD, '    def _get_json_data(self, request):\n        return decode_request(request)\n'),
    ('        self.request_data = self._get_json_data(request)',
     '        try:\n            self.request_data = self._get_json_data(request)\n'
     '        except RequestRejected as exc:\n            return JsonResponse({"detail": exc.detail}, status=exc.status)'),
)


def transform(raw):
    if hashlib.sha256(raw).hexdigest() != INPUT_SHA256:
        raise ValueError('Unreviewed guarded Santa input')
    text = raw.decode('utf-8')
    for old, new in PATCHES:
        if text.count(old) != 1:
            raise ValueError('Santa request source shape changed')
        text = text.replace(old, new, 1)
    result = (NOTICE + text).encode('utf-8')
    ast.parse(result, filename=SOURCE)
    if hashlib.sha256(result).hexdigest() != OUTPUT_SHA256:
        raise ValueError('Unreviewed bounded Santa output')
    return result


def docker_program(source_root, module_path):
    if hashlib.sha256((Path(source_root) / SOURCE).read_bytes()).hexdigest() != UPSTREAM_SHA256:
        raise ValueError('Unreviewed upstream Santa source')
    module = Path(module_path).read_bytes().replace(b'\r\n', b'\n')
    ast.parse(module, filename='azd_santa_request_limits.py')
    digest = hashlib.sha256(module).hexdigest()
    program = (
        'import ast,base64,hashlib\nfrom pathlib import Path\n'
        f'path=Path("/zentral")/{SOURCE!r}\nsource=path.read_bytes()\n'
        f'if hashlib.sha256(source).hexdigest()!={INPUT_SHA256!r}: raise RuntimeError("Santa limits input mismatch")\n'
        f'text=source.decode("utf-8")\npatches={PATCHES!r}\n'
        'for old,new in patches:\n'
        '    if text.count(old)!=1: raise RuntimeError("Santa limits shape mismatch")\n'
        '    text=text.replace(old,new,1)\n'
        f'result=({NOTICE!r}+text).encode("utf-8")\n'
        f'if hashlib.sha256(result).hexdigest()!={OUTPUT_SHA256!r}: raise RuntimeError("Santa limits output mismatch")\n'
        f'module=base64.b64decode({base64.b64encode(module).decode()!r})\n'
        f'if hashlib.sha256(module).hexdigest()!={digest!r}: raise RuntimeError("Santa limits helper mismatch")\n'
        'ast.parse(result)\nast.parse(module)\n'
        'path.write_bytes(result)\n'
        'Path("/zentral/server/azd_santa_request_limits.py").write_bytes(module)\n'
    )
    return program, digest
