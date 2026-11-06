"""Original bounded Santa public-v1 JSON input boundary. Unlicense.

No Django dependency: the pinned real handler translates RequestRejected into
an HTTP response. Limits are per request, not a substitute for ingress limits.
"""
import json
import math
import os
import zlib
from dataclasses import dataclass


@dataclass(frozen=True)
class Limits:
    compressed: int = 1024 * 1024
    expanded: int = 4 * 1024 * 1024
    depth: int = 32
    events: int = 100


def configured_limits(environ):
    values = {}
    for name, default, ceiling in (
        ('compressed', 1024 * 1024, 4 * 1024 * 1024),
        ('expanded', 4 * 1024 * 1024, 16 * 1024 * 1024),
        ('depth', 32, 64), ('events', 100, 1000),
    ):
        raw = environ.get('AZD_SANTA_MAX_' + name.upper(), str(default))
        if not isinstance(raw, str) or not raw.isascii() or not raw.isdecimal():
            raise ValueError('Invalid Santa request limit: ' + name)
        value = int(raw)
        if not 1 <= value <= ceiling:
            raise ValueError('Santa request limit outside hard bounds: ' + name)
        values[name] = value
    return Limits(**values)


# Invalid deployment configuration prevents application startup.
DEFAULT_LIMITS = configured_limits(os.environ)
EVENT_COLLECTIONS = ('events', 'file_access_events', 'audit_events',
                     'network_mount_events', 'network_flow_events', 'usb_mount_events')


class RequestRejected(ValueError):
    def __init__(self, status, detail):
        self.status = status
        self.detail = detail
        super().__init__(detail)


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate JSON member')
        result[key] = value
    return result


def _constant(value):
    raise ValueError('Non-finite JSON number')


def _float(value):
    result = float(value)
    if not math.isfinite(result):
        raise ValueError('Non-finite JSON number')
    return result


def _check_depth(text, maximum):
    depth = 0
    quoted = escaped = False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == '\\':
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in '[{':
            depth += 1
            if depth > maximum:
                raise RequestRejected(400, 'JSON nesting limit exceeded')
        elif char in ']}':
            depth -= 1
    # Full JSON syntax validation follows; this only bounds parser recursion.


def decode_bytes(raw, encoding=None, *, limits=DEFAULT_LIMITS):
    if len(raw) > limits.compressed:
        raise RequestRejected(413, 'Request body limit exceeded')
    if not isinstance(encoding, (str, type(None))):
        raise RequestRejected(415, 'Unsupported Content-Encoding')
    encoding = (encoding or '').strip().lower()
    if encoding in ('deflate', 'zlib', 'gzip'):
        decoder = zlib.decompressobj(31 if encoding == 'gzip' else 15)
        try:
            raw = decoder.decompress(raw, limits.expanded + 1)
        except zlib.error:
            raise RequestRejected(400, 'Invalid compressed request') from None
        if len(raw) > limits.expanded or decoder.unconsumed_tail:
            raise RequestRejected(413, 'Expanded body limit exceeded')
        if not decoder.eof or decoder.unused_data:
            raise RequestRejected(400, 'Incomplete or trailing compressed data')
    elif encoding not in ('', 'identity'):
        raise RequestRejected(415, 'Unsupported Content-Encoding')
    if len(raw) > limits.expanded:
        raise RequestRejected(413, 'Expanded body limit exceeded')
    try:
        text = raw.decode('utf-8')
        _check_depth(text, limits.depth)
        data = json.loads(text, object_pairs_hook=_unique, parse_constant=_constant, parse_float=_float)
    except RequestRejected:
        raise
    except (UnicodeError, ValueError, RecursionError):
        raise RequestRejected(400, 'Invalid JSON request') from None
    if not isinstance(data, dict):
        raise RequestRejected(400, 'JSON object required')
    count = 0
    for name in EVENT_COLLECTIONS:
        if name in data:
            events = data[name]
            if not isinstance(events, list) or any(not isinstance(event, dict) for event in events):
                raise RequestRejected(400, 'Invalid event collection')
            count += len(events)
    if count > limits.events:
        raise RequestRejected(413, 'Event batch limit exceeded')
    return data


def decode_request(request, *, limits=DEFAULT_LIMITS):
    # Bound the read itself, including requests without a Content-Length. Never
    # materialize request.body first: Django's general limit is much larger.
    length = request.META.get('CONTENT_LENGTH')
    if length not in (None, ''):
        if not isinstance(length, str) or not length.isascii() or not length.isdecimal():
            raise RequestRejected(400, 'Invalid Content-Length')
        if len(length) > 12 or int(length) > limits.compressed:
            raise RequestRejected(413, 'Request body limit exceeded')
    raw = request.read(limits.compressed + 1)
    return decode_bytes(raw, request.META.get('HTTP_CONTENT_ENCODING'), limits=limits)
