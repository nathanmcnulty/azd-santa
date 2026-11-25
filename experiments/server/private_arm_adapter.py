"""Original Unlicense. Private, explicit cached-CLI ARM capability callback.

No command-line entry point: tokens/capabilities must remain in the operator
process. This transport is not a grant, trusted capture proof or guest relay.
"""
import copy
from dataclasses import dataclass
import datetime as dt
import http.client
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import ssl
import subprocess
import threading
import time

import backup_store_selection as selector
import blob_retention as retention

BOUND = 262144
HOST = 'management.azure.com'
RESOURCE = 'https://' + HOST + '/'


class ArmRejected(ValueError):
    def __init__(self):
        super().__init__('Private ARM attempt rejected or unknown; do not replay')


def require(condition):
    if not condition:
        raise ArmRejected()


def decoded(raw):
    require(type(raw) is bytes and len(raw) <= BOUND)
    value = json.loads(raw, object_pairs_hook=retention.unique,
                       parse_constant=lambda _: (_ for _ in ()).throw(ArmRejected()))
    require(type(value) is dict)
    return value


@dataclass(frozen=True)
class Selection:
    tenant: str
    subscription: str
    store: retention.Store
    source: retention.SelectedTarget
    verifier: retention.SelectedTarget | None = None

    def intent(self):
        def target(value):
            if value is None:
                return None
            group = value.vm_id.split('/providers/')[0].rsplit('/', 1)[1]
            require(group.startswith('rg-azd-santa-vm-'))
            return dict(environment=group[len('rg-azd-santa-vm-'):], instance=value.instance_id)
        intent = dict(tenant=self.tenant, subscription=self.subscription,
                      region=self.store.region, owner=self.store.ownership_id,
                      store_group=self.store.blob.account_id.split('/providers/')[0].rsplit('/', 1)[1],
                      store_name=self.store.blob.account, source=target(self.source), verifier=target(self.verifier))
        store, targets, _ = selector.plan(intent)
        require(store.blob.account_id == self.store.blob.account_id
                and store.region == self.store.region and store.ownership_id == self.store.ownership_id
                and store.owned_subnets == self.store.owned_subnets
                and targets == [t for t in (self.source, self.verifier) if t is not None])
        return intent


def file_identity(path):
    value = path.stat()
    return value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns


def resolve_cli():
    """Resolve once per attempt; installation/PATH trust is external authority."""
    value = shutil.which('az')
    require(type(value) is str and Path(value).is_absolute())
    path = Path(value).resolve(strict=True)
    require(path.is_file() and not any(c in str(path) for c in '%!&|<>^"\r\n'))
    if os.name == 'nt':
        require(path.name.casefold() in ('az.cmd', 'az.exe'))
    return path, file_identity(path)


def cached_cli(arguments, seconds, *, application=None):
    """Bound stdout while running only fixed cached-profile CLI commands.

    CLI/MSAL may refresh its existing cache. No login fallback is implemented.
    The installed CLI and OS process/network policy remain trusted prerequisites.
    """
    require(0 < seconds <= 30)
    require(arguments == ['version'] or
            (len(arguments) in (4, 6) and arguments[:2] in
             (['account', 'show'], ['account', 'get-access-token'])
             and arguments[2] == '--subscription' and re.fullmatch(retention.GUID, arguments[3])
             and ((arguments[1] == 'show' and len(arguments) == 4) or
                  (arguments[1] == 'get-access-token' and arguments[4:] == ['--resource', RESOURCE]))))
    return bounded_cli(arguments, seconds, application=application)


def bounded_cli(arguments, seconds, *, application=None):
    """Run arguments prevalidated by a fixed-purpose CLI adapter."""
    require(0 < seconds <= 1200)
    deadline = time.monotonic() + seconds
    path, identity = application if application is not None else resolve_cli()
    require(file_identity(path) == identity)
    env = os.environ.copy()
    env.update(AZURE_LOGGING_ENABLE_LOG_FILE='false', AZURE_CORE_COLLECT_TELEMETRY='false',
               AZURE_CORE_ONLY_SHOW_ERRORS='true', AZURE_CORE_NO_COLOR='true',
               AZURE_EXTENSION_USE_DYNAMIC_INSTALL='no', AZURE_AUTO_UPGRADE_ENABLE='no')
    for key in list(env):
        if key.casefold() in ('http_proxy', 'https_proxy', 'all_proxy'):
            del env[key]
    env['NO_PROXY'] = '*'
    flags = subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP if os.name == 'nt' else 0
    argv = [str(path), *arguments, '--only-show-errors', '--output', 'json']
    # Batch launch is an OS shell boundary even with shell=False. All arguments
    # must be validated by the caller; quote the trusted path explicitly.
    command = ('"' + str(path) + '" ' + subprocess.list2cmdline(argv[1:])) if os.name == 'nt' else argv
    process = subprocess.Popen(command,
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        shell=False, env=env, creationflags=flags, start_new_session=os.name != 'nt')
    result = bytearray()
    done = threading.Event()
    failed = []
    def read():
        try:
            while True:
                chunk = process.stdout.read1(8192)
                if not chunk:
                    break
                require(len(result) + len(chunk) <= 65536)
                result.extend(chunk)
        except Exception:
            failed.append(True)
        finally:
            done.set()
    thread = threading.Thread(target=read, daemon=True)
    thread.start()
    try:
        require(done.wait(max(0, deadline - time.monotonic())))
        require(not failed and process.wait(timeout=max(.001, deadline - time.monotonic())) == 0)
        require(time.monotonic() <= deadline)
        return decoded(bytes(result))
    except Exception:
        try:
            if os.name == 'nt':
                taskkill = Path(os.environ['SystemRoot']) / 'System32/taskkill.exe'
                require(taskkill.is_absolute() and taskkill.is_file())
                subprocess.run([str(taskkill), '/PID', str(process.pid), '/T', '/F'],
                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    timeout=5, creationflags=subprocess.CREATE_NO_WINDOW, check=False)
            else:
                os.killpg(process.pid, signal.SIGKILL)
        except Exception:
            pass
        try:
            process.kill()
        except Exception:
            pass
        raise ArmRejected() from None
    finally:
        try:
            process.stdout.close()
        except Exception:
            pass
        result.clear()


def https(method, url, body, token, deadline):
    """Direct TLS, no environment proxy, redirect, retry or raw error response."""
    require(url.startswith(RESOURCE) and method in ('GET', 'POST'))
    connection = http.client.HTTPSConnection(HOST, 443, context=ssl.create_default_context(),
        timeout=max(.001, min(15, deadline - time.monotonic())))
    sockets = []
    def interrupt():
        # Shutdown interrupts getresponse/read1 even for slow-drip headers and
        # HTTPResponse-held socket refs; close alone need not interrupt them.
        for sock in sockets:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
    timer = None
    try:
        require(time.monotonic() < deadline)
        connection.connect()
        require(time.monotonic() < deadline)
        sock = connection.sock
        sockets.append(sock)
        timer = threading.Timer(max(0, deadline - time.monotonic()), interrupt)
        timer.daemon = True
        timer.start()
        require(time.monotonic() < deadline)
        sock.settimeout(min(15, deadline - time.monotonic()))
        headers = {'Authorization': 'Bearer ' + token, 'Accept': 'application/json', 'Accept-Encoding': 'identity'}
        payload = None if body is None else retention.encoded(body)
        if payload is not None:
            headers['Content-Type'] = 'application/json'
        connection.request(method, '/' + url[len(RESOURCE):], body=payload, headers=headers)
        response = connection.getresponse()
        require(response.status == 200 and response.getheader('Content-Encoding', 'identity') == 'identity')
        length = response.getheader('Content-Length')
        require(length is None or (re.fullmatch(r'0|[1-9][0-9]{0,6}', length) and int(length) <= BOUND))
        raw = bytearray()
        while True:
            require(time.monotonic() < deadline)
            sock.settimeout(min(15, deadline - time.monotonic()))
            chunk = response.read1(min(8192, BOUND + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
            require(len(raw) <= BOUND)
        require(length is None or len(raw) == int(length))
        return decoded(bytes(raw))
    except Exception:
        raise ArmRejected() from None
    finally:
        if timer is not None:
            timer.cancel()
        connection.close()


class CachedStoreObservation:
    """Shared cached context, bounded ARM transport and exact store readback."""

    def __init__(self, selection, *, seconds, cli, transport):
        require(type(selection) is Selection and type(seconds) is int and 1 <= seconds <= 300)
        self._intent = selection.intent()
        self._selection = selection
        self._urls = frozenset(selector.plan(self._intent)[2])
        self._post = RESOURCE.rstrip('/') + selection.store.blob.account_id + '/listServiceSas?api-version=2025-06-01'
        self._cli, self._transport, self._seconds = cli, transport, seconds
        self._token = None
        self._state = 'new'
        self._requests = self._bytes = 0
        self._busy = threading.Lock()

    def __repr__(self):
        return '<private cached ARM attempt>'

    def __getstate__(self):
        raise ArmRejected()

    def _remaining(self):
        remaining = self._deadline - time.monotonic()
        require(remaining > 0)
        return min(30, remaining)

    def _context(self):
        context = self._cli(['account', 'show', '--subscription', self._intent['subscription']], self._remaining())
        require(type(context) is dict and context.get('id', '').casefold() == self._intent['subscription']
                and context.get('tenantId', '').casefold() == self._intent['tenant']
                and context.get('state') == 'Enabled' and context.get('environmentName') == 'AzureCloud')
        user = context.get('user')
        require(type(user) is dict and user.get('type') in ('user', 'servicePrincipal')
                and not user.get('cloudShellID') and not user.get('assignedIdentityInfo')
                and user.get('name') not in ('systemAssignedIdentity', 'userAssignedIdentity'))
        return context

    def _read(self, url):
        self._remaining()
        require(url in self._urls and self._requests < 96)
        self._requests += 1
        result = self._transport('GET', url, None, self._token, self._deadline)
        self._remaining()
        require(type(result) is dict and len(retention.encoded(result)) <= BOUND)
        self._bytes += len(retention.encoded(result))
        require(self._bytes <= 32 * 1024 * 1024)
        return result

    def _observe(self):
        before_context = self._context()
        require(retention.encoded(before_context) == retention.encoded(self._context_initial))
        before = {url: self._read(url) for url in sorted(self._urls)}
        after = {url: self._read(url) for url in sorted(self._urls)}
        after_context = self._context()
        return selector.validate(self._intent, before_context, after_context, before, after)

    def initialize(self, *, live=False):
        require(self._busy.acquire(blocking=False))
        try:
            return self._initialize(live=live)
        finally:
            self._busy.release()

    def _initialize(self, *, live=False):
        require(type(live) is bool and self._state == 'new')
        if not live:
            return dict(scope='private-cached-arm-plan-v1', urls=sorted(self._urls),
                        post_url=self._post, performs_mutation=False, authenticates=False)
        self._state = 'initializing'
        self._deadline = time.monotonic() + self._seconds
        try:
            if self._cli is cached_cli:
                application = resolve_cli()
                self._cli = lambda args, seconds: cached_cli(args, seconds, application=application)
            version = self._cli(['version'], self._remaining()).get('azure-cli', '')
            require(re.fullmatch(r'2\.[0-9]+\.[0-9]+', version)
                    and tuple(map(int, version.split('.'))) >= (2, 54, 0))
            self._context_initial = self._context()
            token = self._cli(['account', 'get-access-token', '--subscription', self._intent['subscription'],
                               '--resource', RESOURCE], self._remaining())
            require(type(token) is dict and set(token) == {'tokenType', 'accessToken', 'expires_on', 'expiresOn', 'tenant', 'subscription'}
                    and token['tokenType'] == 'Bearer' and token['tenant'].casefold() == self._intent['tenant']
                    and token['subscription'].casefold() == self._intent['subscription']
                    and type(token['expires_on']) is int and token['expires_on'] > time.time() + self._seconds + 30)
            secret = token['accessToken']
            require(type(secret) is str and 1 <= len(secret) <= 32768 and secret.isascii()
                    and all(33 <= ord(c) <= 126 for c in secret))
            self._token = secret
            require(retention.encoded(self._context_initial) == retention.encoded(self._context()))
            receipt = self._observe()
            self._observation_sha = receipt['observation_sha256']
            self._state = 'ready'
            return receipt
        except Exception:
            self._state, self._token = 'closed', None
            raise ArmRejected() from None


class CachedArm(CachedStoreObservation):
    """One native capture capability attempt. Call initialize, then mint and seal."""

    def __init__(self, selection, record, target, permission, *, seconds=180,
                 cli=cached_cli, transport=https):
        super().__init__(selection, seconds=seconds, cli=cli, transport=transport)
        require(target == (selection.source if permission == 'c' else selection.verifier))
        retention.selection(record, selection.store.blob, selection.store, target, permission)
        self._record = copy.deepcopy(record)
        self._target, self._permission = target, permission

    def __call__(self, method, url, body):
        require(self._busy.acquire(blocking=False))
        try:
            return self._call(method, url, body)
        finally:
            self._busy.release()

    def _call(self, method, url, body):
        try:
            require(self._state == 'ready')
            if method == 'GET':
                require(body is None)
                return self._read(url)
            require(method == 'POST' and url == self._post and type(body) is dict
                    and set(body) == {'canonicalizedResource', 'signedResource', 'signedPermission',
                                      'signedProtocol', 'signedStart', 'signedExpiry'})
            require(body['canonicalizedResource'] == self._selection.store.blob.canonical
                    and body['signedResource'] == 'b' and body['signedPermission'] == self._permission
                    and body['signedProtocol'] == 'https')
            stamp = lambda value: dt.datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=dt.timezone.utc)
            start, expiry = stamp(body['signedStart']), stamp(body['signedExpiry'])
            require(start.strftime('%Y-%m-%dT%H:%M:%SZ') == body['signedStart']
                    and expiry.strftime('%Y-%m-%dT%H:%M:%SZ') == body['signedExpiry'])
            now = dt.datetime.now(dt.timezone.utc)
            require(840 <= (now-start).total_seconds() <= 960 and 0 < (expiry-now).total_seconds() <= 900
                    and (expiry-start).total_seconds() == 1800)
            require(self._observe()['observation_sha256'] == self._observation_sha)
            self._remaining()
            # Fence before sending: any exception, including a lost response, is terminal.
            self._state = 'post-attempted'
            response = self._transport(method, url, copy.deepcopy(body), self._token, self._deadline)
            self._remaining()
            require(retention.encoded(self._context()) == retention.encoded(self._context_initial))
            self._state, self._token = 'closed', None
            require(type(response) is dict and set(response) == {'serviceSasToken'}
                    and len(retention.encoded(response)) <= 8192)
            return response
        except Exception:
            self._state, self._token = 'closed', None
            raise ArmRejected() from None

    def mint(self, *, apply=False):
        require(type(apply) is bool)
        return retention.mint_capability(self, self._record, self._selection.store.blob,
            self._selection.store, self._target, self._permission, apply=apply)
