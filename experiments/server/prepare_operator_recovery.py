"""Exact, independently checked recovery layer applied after the operator-MFA layer."""
import ast
import base64
import hashlib
from pathlib import Path

URLS = 'server/server/urls.py'
SETTINGS = 'server/server/settings.py'
ORIGINAL_SETTINGS = '1f302e91ed35a170e1580a8c79c218bb812c6efc09f7850bb41392f9ce6bd2b1'
INPUTS = {
    URLS: '960a48528b53ddace977b12602389e6585c013563b3f6b188dba76439c25f6a3',
    SETTINGS: '8569481c18962c007698dc4492c2ea402eb49ec2fb1d44249274866642fcfb68',
}
OUTPUTS = {URLS: '370be4fdfc808a9e3131bd6182900f23d2b18c1d0e951262beca73c0c84b8194',
           SETTINGS: 'a018cb59b1603b5b6b3cf76cad44571517d1ad0130d92ea9b82700d47f1dc9e5'}
PATCHES = {
    URLS: [('from accounts.views import login\n',
            'from accounts.views import login\nfrom azd_santa_operator_recovery import reset_confirm_view\n'),
           ('auth_views.PasswordResetConfirmView.as_view()', 'reset_confirm_view()')],
    SETTINGS: [('ROOT_URLCONF = \'server.urls\'',
                "PASSWORD_RESET_TIMEOUT = 600  # azd-santa: short-lived operator setup/reset links\nROOT_URLCONF = 'server.urls'")],
}
NOTICE = '# Modified by azd-santa: serialize one-use local operator password setup.\n'
WRAPPER = b'# Original Unlicense operator management command.\nfrom azd_santa_operator_recovery import command_class\nCommand = command_class()\n'


def transform(name, raw):
    if name not in INPUTS or hashlib.sha256(raw).hexdigest() != INPUTS[name]:
        raise ValueError('Unreviewed recovery layer input: ' + name)
    text = raw.decode('utf-8')
    for old, new in PATCHES[name]:
        if text.count(old) != 1:
            raise ValueError('Recovery layer source shape changed: ' + name)
        text = text.replace(old, new, 1)
    output = (NOTICE + text).encode('utf-8')
    ast.parse(output)
    return output


def docker_program(source_root):
    root = Path(source_root)
    urls = (root / URLS).read_bytes()
    settings = (root / SETTINGS).read_bytes()
    if hashlib.sha256(settings).hexdigest() != ORIGINAL_SETTINGS:
        raise ValueError('Unreviewed original settings before recovery integration')
    if hashlib.sha256(transform(URLS, urls)).hexdigest() != OUTPUTS[URLS]:
        raise ValueError('Unreviewed recovery URL output')
    module = Path(__file__).with_name('operator_recovery.py').read_bytes().replace(b'\r\n', b'\n')
    ast.parse(module)
    digest = hashlib.sha256(module).hexdigest()
    destinations = {'server/azd_santa_operator_recovery.py': module,
                    'server/accounts/management/commands/operator_access.py': WRAPPER}
    sealed = Path(__file__).with_name('sealed_setup.py').read_bytes().replace(b'\r\n', b'\n')
    ast.parse(sealed)
    destinations['server/azd_santa_sealed_setup.py'] = sealed
    payload = {name: (base64.b64encode(raw).decode(), hashlib.sha256(raw).hexdigest())
               for name, raw in destinations.items()}
    program = (
        'import ast,base64,hashlib,os\nfrom pathlib import Path\n'
        f'inputs={INPUTS!r}\noutputs={OUTPUTS!r}\npatches={PATCHES!r}\nnotice={NOTICE!r}\npayload={payload!r}\n'
        'for name,expected in inputs.items():\n'
        "    path=Path('/zentral')/name\n    raw=path.read_bytes()\n"
        "    if hashlib.sha256(raw).hexdigest()!=expected: raise RuntimeError('Recovery input mismatch: '+name)\n"
        "    text=raw.decode('utf-8')\n    for old,new in patches[name]:\n"
        "        if text.count(old)!=1: raise RuntimeError('Recovery shape mismatch: '+name)\n"
        '        text=text.replace(old,new,1)\n'
        "    raw=(notice+text).encode('utf-8')\n"
        "    if hashlib.sha256(raw).hexdigest()!=outputs[name]: raise RuntimeError('Recovery output mismatch: '+name)\n"
        '    ast.parse(raw,filename=name)\n    path.write_bytes(raw)\n'
        'for name,(encoded,expected) in payload.items():\n'
        '    raw=base64.b64decode(encoded)\n'
        "    if hashlib.sha256(raw).hexdigest()!=expected: raise RuntimeError('Recovery module mismatch')\n"
        '    ast.parse(raw,filename=name)\n'
        "    path=Path('/zentral')/name\n"
        '    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o644)\n'
        '    with os.fdopen(fd,"wb") as stream: stream.write(raw)\n'
        '    path.chmod(0o644)\n'
        f"print('Installed original operator recovery layer SHA256: {digest}')\n"
        f"print('Installed original setup sealer SHA256: {hashlib.sha256(sealed).hexdigest()}')\n"
    )
    return program
