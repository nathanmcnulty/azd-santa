"""Loopback-only, synthetic v1 subset. NOT a deployable Santa server or client.

No Azure, enrollment, publication, persistence or native-client implementation.
Only the test runner starts this HTTP model; it never accepts external bind inputs.
"""
import base64
import hashlib
import hmac
import json
import re
import secrets
import time
import zlib
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer

MAX_BYTES = 65536
MAX_EVENTS = 50
MAX_EVENT_DIGESTS = 256
STAGES = {'preflight', 'eventupload', 'ruledownload', 'postflight'}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate key')
        result[key] = value
    return result


def decode(raw, encoding):
    if encoding in ('deflate', 'gzip'):
        obj = zlib.decompressobj(15 if encoding == 'deflate' else 31)
        raw = obj.decompress(raw, MAX_BYTES + 1)
        if len(raw) > MAX_BYTES or obj.unconsumed_tail:
            raise OverflowError()
        if not obj.eof or obj.unused_data:
            raise ValueError('incomplete or concatenated stream')
    elif encoding:
        raise LookupError()
    if len(raw) > MAX_BYTES:
        raise OverflowError()
    value = json.loads(raw.decode('utf-8'), object_pairs_hook=unique_object,
                       parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    if not isinstance(value, dict):
        raise ValueError('object required')
    return value


@dataclass(frozen=True)
class Snapshot:
    """Test-only immutable snapshot. An approval label is NOT real approval."""
    revision: int
    rules: tuple  # canonical JSON bytes, preventing mutation through nested dictionaries
    approval: str

    @classmethod
    def fixture(cls, revision, rules, approval='synthetic-only'):
        if type(revision) is not int or revision < 1 or len(rules) > 100 or not approval:
            raise ValueError('invalid fixture')
        for rule in rules:
            if set(rule) != {'identifier', 'policy', 'rule_type'}:
                raise ValueError('only fixture rule subset supported')
            if rule['rule_type'] not in ('BINARY', 'SIGNINGID') or rule['policy'] not in ('BLOCKLIST', 'ALLOWLIST'):
                raise ValueError('unsupported fixture rule')
        return cls(revision, tuple(canonical(r) for r in rules), approval)


class Model:
    def __init__(self, snapshot):
        self.snapshot = snapshot
        # Ephemeral, synthetic values, never usable outside this process.
        self.tokens = {secrets.token_urlsafe(32): 'device-a', secrets.token_urlsafe(32): 'device-b'}
        self.key = secrets.token_bytes(32)
        self.sessions = {}
        self.acknowledged = {}
        self.event_digests = {d: set() for d in self.tokens.values()}
        self.audit = []
        self.now = time.monotonic

    def revoke_fixture_device(self, device):
        """Test-only revocation; remove all fake credentials and active cursors."""
        self.tokens = {token: bound for token, bound in self.tokens.items() if bound != device}
        self.sessions.pop(device, None)

    def rotate_fixture_device(self, device):
        self.revoke_fixture_device(device)
        token = secrets.token_urlsafe(32)
        self.tokens[token] = device
        return token

    def cursor(self, device, session, offset):
        payload = canonical([device, session['id'], session['snapshot'].revision, offset])
        return base64.urlsafe_b64encode(payload + hmac.digest(self.key, payload, 'sha256')).decode()

    def offset(self, cursor, device, session):
        if not isinstance(cursor, str) or len(cursor) > 512:
            raise ValueError()
        try:
            raw = base64.b64decode(cursor, altchars=b'-_', validate=True)
            payload, mac = raw[:-32], raw[-32:]
            if not hmac.compare_digest(mac, hmac.digest(self.key, payload, 'sha256')):
                raise ValueError()
            values = json.loads(payload)
            offset = values[3]
            if values[:3] != [device, session['id'], session['snapshot'].revision]:
                raise ValueError()
            if type(offset) is not int or offset < 1 or offset >= len(session['snapshot'].rules):
                raise ValueError()
            return offset
        except (ValueError, IndexError, TypeError):
            raise ValueError('invalid cursor') from None

    def handle(self, stage, device, body):
        if body.get('machine_id') != device:
            return 403, {}
        if stage == 'preflight':
            snapshot = self.snapshot
            # Neither emptiness nor a label is permission to wipe a real Mac.
            if not snapshot.rules or not snapshot.approval:
                return 503, {}
            if snapshot.revision < self.acknowledged.get(device, 0):
                return 409, {}
            # A repeated identical preflight pins the same session until expiry.
            session = self.sessions.get(device)
            if session is None or self.now() >= session['expires'] or session['acked']:
                self.sessions[device] = dict(id=secrets.token_hex(16), snapshot=snapshot,
                                            expires=self.now() + 300, served=set(), acked=False)
            return 200, {'clientMode': 'MONITOR', 'syncType': 'CLEAN', 'batchSize': MAX_EVENTS}
        session = self.sessions.get(device)
        if not session or self.now() >= session['expires']:
            return 409, {}
        snapshot = session['snapshot']
        if stage == 'eventupload':
            # Public v1 has no event_id. Dedupe whole canonical event per device,
            # bounded in memory; identical real executions can be conflated.
            events = body.get('events')
            if not isinstance(events, list) or not 1 <= len(events) <= MAX_EVENTS:
                return 400, {}
            if any(not isinstance(e, dict) or not isinstance(e.get('file_sha256'), str)
                   or not re.fullmatch('[a-f0-9]{64}', e['file_sha256'])
                   or e.get('decision') not in ('BLOCK_BINARY', 'BLOCK_UNKNOWN', 'ALLOW_UNKNOWN') for e in events):
                return 400, {}
            digests = {hashlib.sha256(canonical(e)).hexdigest() for e in events}
            combined = self.event_digests[device] | digests
            if len(combined) > MAX_EVENT_DIGESTS:
                return 429, {}
            self.event_digests[device] = combined
            return 200, {}
        if stage == 'ruledownload':
            try:
                cursor_value = body.get('cursor', '')
                if not isinstance(cursor_value, str):
                    raise ValueError()
                offset = self.offset(cursor_value, device, session) if cursor_value else 0
            except ValueError:
                return 400, {}
            # One rule/page deliberately forces paging. Replays return identical data.
            rule = json.loads(snapshot.rules[offset])
            session['served'].add(offset)
            cursor = self.cursor(device, session, offset + 1) if offset + 1 < len(snapshot.rules) else ''
            return 200, {'rules': [rule], 'cursor': cursor}
        if stage == 'postflight':
            count = len(snapshot.rules)
            received, processed = body.get('rules_received'), body.get('rules_processed')
            if (type(received) is not int or type(processed) is not int or received != count or processed != count
                    or session['served'] != set(range(count)) or body.get('syncType') != 'CLEAN'):
                return 409, {}
            self.acknowledged[device] = snapshot.revision
            session['acked'] = True
            return 200, {}  # Report only, never an endpoint-enforcement receipt.
        return 404, {}


class Handler(BaseHTTPRequestHandler):
    server_version = 'SyntheticLoopback/1'
    sys_version = ''

    def log_message(self, *args):
        pass  # Do not log path, authorization or raw payload.

    def reply(self, status, body):
        # The local harness sends its request before reading a rejection. Drain
        # at most one bounded body (including the one-byte oversize test) so
        # Windows does not reset the socket with the HTTP rejection unread.
        # Never decode it or grow the accepted JSON limit for this transport fix.
        if self.command == 'POST' and not getattr(self, 'body_consumed', False):
            lengths = self.headers.get_all('Content-Length', [])
            try:
                size = int(lengths[0]) if len(lengths) == 1 else -1
                if 0 <= size <= MAX_BYTES + 1 and not self.headers.get('Transfer-Encoding'):
                    self.connection.settimeout(2)
                    self.rfile.read(size)
            except (ValueError, OSError):
                pass
            self.body_consumed = True
        request_id = secrets.token_hex(8)
        self.server.model.audit.append((request_id, status))
        del self.server.model.audit[:-128]
        raw = canonical(body)
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(raw)))
        self.send_header('X-Request-ID', request_id)
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(raw)
        self.wfile.flush()
        self.close_connection = True

    def send_error(self, code, message=None, explain=None):
        self.reply(code, {})

    def do_GET(self):
        self.reply(405, {})

    def do_POST(self):
        self.connection.settimeout(2)
        match = re.fullmatch('/(preflight|eventupload|ruledownload|postflight)/(device-[ab])', self.path)
        if not match:
            return self.reply(404, {})
        stage, device = match.groups()
        headers = self.headers.get_all('Authorization', [])
        token = headers[0][7:] if len(headers) == 1 and headers[0].startswith('Bearer ') else ''
        if self.server.model.tokens.get(token) != device:
            return self.reply(401, {})
        # Identity forwarding is deliberately not implemented or trusted.
        if self.headers.get('Transfer-Encoding') or len(self.headers.get_all('Content-Length', [])) != 1:
            return self.reply(400, {})
        try:
            length = int(self.headers['Content-Length'])
            if not 0 <= length <= MAX_BYTES:
                return self.reply(413, {})
        except ValueError:
            return self.reply(400, {})
        if self.headers.get('Content-Type') != 'application/json':
            return self.reply(415, {})
        try:
            self.body_consumed = True
            raw = self.rfile.read(length)
            if len(raw) != length:
                raise ValueError('truncated request')
            body = decode(raw, self.headers.get('Content-Encoding', ''))
            status, response = self.server.model.handle(stage, device, body)
        except OverflowError:
            status, response = 413, {}
        except LookupError:
            status, response = 415, {}
        except (ValueError, UnicodeError, zlib.error, RecursionError, TimeoutError):
            status, response = 400, {}
        self.reply(status, response)


def loopback_server(model):
    server = HTTPServer(('127.0.0.1', 0), Handler)
    server.model = model
    return server
