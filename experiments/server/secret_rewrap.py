"""Original Unlicense in-memory secret rewrap, never restore or activation.

Only complete concrete Store/Action/StateVersion projections are accepted. Caller
owns the separate SQL/schema census and confidential handling of returned rows.
Fernet/noop upstream formats do NOT authenticate their context arguments.
"""
import base64
import copy
from dataclasses import dataclass, field
import json
from pathlib import Path
import re
import uuid
import zlib

COMMIT = '88e67b3ce49033aab028029937a6e14f7c489073'
APPS = ('accounts', 'realms', 'zentral.core.compliance_checks',
        'zentral.core.incidents', 'zentral.core.probes', 'zentral.core.stores',
        'zentral.core.terraform', 'zentral.contrib.inventory', 'zentral.contrib.santa')
STORE_FIELDS = frozenset(('id', 'name', 'description', 'created_at', 'updated_at',
    'provisioning_uid', 'slug', 'admin_console', 'event_filters', 'backend', 'backend_kwargs'))
STATE_FIELDS = frozenset(('id', 'state_id', 'encryption_key', 'data', 'created_by_id',
                         'created_by_username', 'created_at'))
ACTION_FIELDS = frozenset(('id', 'name', 'description', 'created_at', 'updated_at',
                          'backend', 'backend_kwargs'))
MAX_ROWS = 10000
MAX_BYTES = 32 * 1024 * 1024
MAX_VALUE = 1024 * 1024
MAX_STATE = 16 * 1024 * 1024


class RewrapRejected(ValueError):
    """Fixed message only; never include an engine/crypto/input exception."""


def require(ok):
    if not ok:
        raise RewrapRejected('Offline secret rewrap rejected; preserve original inputs')


@dataclass(repr=False)
class Material:
    kind: str
    passwords: tuple = ()
    signing_salt: str = ''

    def __repr__(self):
        return '<secret engine material>'


@dataclass
class Result:
    # Sensitive caller-owned rows deliberately excluded from repr and receipt.
    stores: list = field(repr=False)
    actions: list = field(repr=False)
    state_versions: list = field(repr=False)
    receipt: dict


class Engine:
    def __init__(self, name, material):
        require(type(name) is str and re.fullmatch(r'[A-Za-z0-9_-]{1,64}', name))
        require(type(material) is Material)
        self.name = name
        self.noop = name == 'noop'
        require(material.kind == ('noop' if self.noop else 'fernet'))
        if self.noop:
            require(material.passwords == () and material.signing_salt == '')
            return
        require(type(material.passwords) is tuple and 1 <= len(material.passwords) <= 8)
        require(type(material.signing_salt) is str and 1 <= len(material.signing_salt) <= 4096)
        from cryptography.fernet import Fernet, MultiFernet
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        fernets = []
        for password in material.passwords:
            require(type(password) is str and 1 <= len(password) <= 4096)
            kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                salt=material.signing_salt.encode('utf-8'), iterations=100000)
            fernets.append(Fernet(base64.urlsafe_b64encode(kdf.derive(password.encode('utf-8')))))
        self.fernet = MultiFernet(fernets)

    def decrypt(self, payload, context):
        # Retain exact context at this boundary; these two pinned backends ignore it.
        if self.noop:
            raw = base64.b64decode(payload, altchars=b'-_', validate=True)
            require(base64.urlsafe_b64encode(raw).decode('ascii') == payload)
            return raw
        return self.fernet.decrypt(payload.encode('ascii'))

    def encrypt(self, raw, context):
        return self.fernet.encrypt(raw).decode('ascii')


def bounded(value, budget, depth=0):
    require(depth <= 32)
    budget[0] += 1
    require(budget[0] <= 200000)
    if type(value) in (str, bytes):
        budget[1] += len(value.encode('utf-8') if type(value) is str else value)
    elif type(value) is dict:
        for key, item in value.items():
            require(type(key) is str and len(key) <= 256)
            bounded(key, budget, depth + 1); bounded(item, budget, depth + 1)
    elif type(value) is list:
        for item in value:
            bounded(item, budget, depth + 1)
    else:
        require(value is None or type(value) in (int, bool, float))
        if type(value) is float:
            require(value == value and abs(value) != float('inf'))
    require(budget[1] <= MAX_BYTES)


def context(model, pk, path):
    return {'model': model, 'pk': pk, 'field': '.'.join(path)}


def state_data(key, data):
    from cryptography.fernet import Fernet
    require(type(data) is bytes and len(data) <= MAX_STATE)
    compressed = Fernet(key).decrypt(data)
    decoder = zlib.decompressobj()
    plain = decoder.decompress(compressed, MAX_STATE + 1)
    require(len(plain) <= MAX_STATE and decoder.eof and not decoder.unused_data
            and not decoder.unconsumed_tail)
    return plain


def rewrap_projection(*, apps, stores, actions, state_versions, expected_contexts,
                      old_material, new_material, targets):
    """Return a new private projection only after every value verifies.

    targets explicitly maps every observed old engine name to a new name. Noop
    maps only to noop; Fernet maps only to Fernet. expected_contexts is a complete
    ordered selection inventory, not authentication of old token provenance or
    proof of a complete database census. No writes, SQL, stdout or network I/O;
    only the bundled nonsecret declaration lock is read from disk.
    """
    try:
        return _rewrap(apps, stores, actions, state_versions, expected_contexts,
                       old_material, new_material, targets)
    except Exception:
        raise RewrapRejected('Offline secret rewrap rejected; preserve original inputs') from None


def _rewrap(apps, stores, actions, state_versions, expected_contexts, old_material, new_material, targets):
    require(type(apps) in (list, tuple) and tuple(apps) == APPS)
    require(type(stores) is list and type(actions) is list and type(state_versions) is list
            and len(stores) + len(actions) + len(state_versions) <= MAX_ROWS)
    require(type(expected_contexts) is list)
    bounded([stores, actions, state_versions, expected_contexts], [0, 0])
    require(type(old_material) is dict and type(new_material) is dict and type(targets) is dict)
    require(1 <= len(old_material) <= 16 and 1 <= len(new_material) <= 16
            and set(targets) == set(old_material))
    require(all(type(v) is str and v in new_material for v in targets.values()))
    old = {name: Engine(name, value) for name, value in old_material.items()}
    new = {name: Engine(name, value) for name, value in new_material.items()}
    require(all(old[name].noop == new[target].noop for name, target in targets.items()))
    lock = json.loads(Path(__file__).with_name('secret-rewrap-source.lock.json').read_bytes())
    # Validate the entire selection before performing even an in-memory rewrite.
    cells = []; seen_states = set()
    def collect(root, pattern, actual, model, pk, parent, key):
        if not pattern:
            require(root is None or type(root) is str)
            if root is not None:
                cells.append((parent, key, context(model, pk, actual), False))
            return
        if root is None:
            return
        if pattern[0] == '*':
            require(type(root) is list)
            for i, value in enumerate(root):
                collect(value, pattern[1:], actual + [str(i)], model, pk, root, i)
        else:
            require(type(root) is dict)
            if pattern[0] in root:
                collect(root[pattern[0]], pattern[1:], actual + [pattern[0]], model, pk, root, pattern[0])
    output_stores = copy.deepcopy(stores); output_actions = copy.deepcopy(actions)
    output_states = copy.deepcopy(state_versions)
    for rows, fields, model, declarations in (
            (output_stores, STORE_FIELDS, 'stores.store', lock['stores']),
            (output_actions, ACTION_FIELDS, 'probes.action', lock['actions'])):
        seen = set()
        for row in rows:
            require(type(row) is dict and set(row) == fields)
            pk = row['id']
            require(type(pk) is str and str(uuid.UUID(pk)) == pk and pk not in seen)
            seen.add(pk)
            require(type(row['backend']) is str and row['backend'] in declarations)
            declaration = declarations[row['backend']]; kwargs = row['backend_kwargs']
            require(type(kwargs) is dict and set(kwargs) <= set(declaration['kwargs_keys']))
            if 'headers' in kwargs and kwargs['headers'] is not None:
                require(type(kwargs['headers']) is list)
                require(all(type(h) is dict and set(h) == {'name', 'value'} and type(h['name']) is str
                            for h in kwargs['headers']))
            if 'aws_auth' in kwargs and kwargs['aws_auth'] is not None:
                require(type(kwargs['aws_auth']) is dict and set(kwargs['aws_auth']) <=
                        {'aws_access_key_id', 'aws_secret_access_key', 'region_name'})
            for path in declaration['encrypted_kwargs_paths']:
                collect(kwargs, path, [], model, pk, None, None)
    for row in output_states:
        require(type(row) is dict and set(row) == STATE_FIELDS)
        pk = row['id']
        require(type(pk) is int and 0 < pk <= 2**63 - 1 and pk not in seen_states)
        seen_states.add(pk)
        cells.append((row, 'encryption_key', context('terraform.stateversion', pk, ['encryption_key']), True))
    require(json.dumps(expected_contexts, sort_keys=True, allow_nan=False) ==
            json.dumps([cell[2] for cell in cells], sort_keys=True, allow_nan=False))
    changed = noop = plaintext_bytes = 0
    for parent, key, ctx, terraform in cells:
        token = parent[key]
        require(type(token) is str and len(token) <= MAX_VALUE and token.count('$') == 1)
        name, payload = token.split('$')
        require(name in old and len(payload) <= MAX_VALUE)
        raw = old[name].decrypt(payload, ctx)
        require(len(raw) <= MAX_VALUE)
        if not terraform:
            raw.decode('utf-8')  # pinned Store.get_kwargs uses decrypt_str
        before = state_data(raw, parent['data']) if terraform else None
        plaintext_bytes += len(raw) + (len(before) if terraform else 0)
        require(plaintext_bytes <= MAX_BYTES)
        if old[name].noop:
            replacement = token; noop += 1
        else:
            target = targets[name]
            replacement = target + '$' + new[target].encrypt(raw, ctx); changed += 1
        after_name, after_payload = replacement.split('$')
        recovered = new[after_name].decrypt(after_payload, ctx)
        require(recovered == raw)
        if terraform:
            require(state_data(recovered, parent['data']) == before)
        parent[key] = replacement
    return Result(output_stores, output_actions, output_states, dict(scope='offline-secret-rewrap-projection-v1',
        source_commit=COMMIT, stores=len(stores), actions=len(actions), state_versions=len(state_versions),
        inspected=len(cells), rewrapped=changed, noop_preserved=noop,
        restore_accepted=False, current_authority_established=False))
