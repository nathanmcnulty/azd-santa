"""Hash-bound core entrypoint integration for original database authority code."""
import ast
import base64
import hashlib
import json
from pathlib import Path

INPUT = 'c11a6a75841a7c6f719367445a8d604a0cd8e4c9cfb39efe439d09999b2dbef7'
OUTPUT = '2789954887836f03fdc24bf42f0d12eb95109920f66911884200a95c3579a8f6'
HEADER = b'#!/usr/bin/env python\n# -*- coding:utf-8 -*-\n'
NOTICE = b'# Modified by azd-santa: explicit privileged database initialization; restricted runtime startup.\n'
OLD = b'            wait_for_db_migration()\n            wait_for_provisioning()\n            create_zentral_superuser()\n'
NEW = b"            subprocess.run(['python', 'server/manage.py', 'operator_database', 'check'], check=True)\n"


def transform(raw):
    if hashlib.sha256(raw).hexdigest() != INPUT or raw.count(OLD) != 1 or not raw.startswith(HEADER):
        raise ValueError('Unreviewed upstream database entrypoint')
    result = HEADER + NOTICE + raw[len(HEADER):].replace(OLD, NEW)
    ast.parse(result)
    if hashlib.sha256(result).hexdigest() != OUTPUT:
        raise ValueError('Database entrypoint output mismatch')
    return result


def docker_program(source):
    output = transform((Path(source) / 'docker-entrypoint.py').read_bytes())
    module = Path(__file__).with_name('database_roles.py').read_bytes().replace(b'\r\n', b'\n')
    ast.parse(module)
    wrapper = b'from azd_santa_database_roles import command_class\nCommand = command_class()\n'
    payload = {'/zentral/database-role-entrypoint.py': output,
               '/zentral/server/azd_santa_database_roles.py': module,
               '/zentral/server/accounts/management/commands/operator_database.py': wrapper,
               '/zentral/server/DATABASE_ROLE_NOTICE.json': json.dumps({
                   'scope': 'unofficial core database role candidate; not live qualification',
                   'source': 'https://github.com/zentralopensource/zentral/tree/88e67b3ce49033aab028029937a6e14f7c489073',
                   'entrypoint_input_sha256': INPUT, 'entrypoint_output_sha256': OUTPUT,
                   'original_unlicense_database_module_sha256': hashlib.sha256(module).hexdigest(),
                   'normal_startup': 'runtime authority/schema/store check; explicit privileged initialization required',
                   'runtime_temp_permission': 'pinned inventory cleanup requires TEMPORARY; permanent schema creation denied'},
                   sort_keys=True).encode()}
    program = 'import base64,hashlib,os\nfrom pathlib import Path\n'
    program += "p=Path('/zentral/docker-entrypoint.py')\n"
    program += f"if hashlib.sha256(p.read_bytes()).hexdigest()!={INPUT!r}: raise RuntimeError('Database entrypoint input mismatch')\n"
    for name, raw in payload.items():
        mode = 0o755 if name == '/zentral/database-role-entrypoint.py' else 0o644
        digest = hashlib.sha256(raw).hexdigest()
        program += f"raw=base64.b64decode({base64.b64encode(raw).decode()!r})\n"
        program += f"if hashlib.sha256(raw).hexdigest()!={digest!r}: raise RuntimeError('Database layer byte mismatch')\n"
        program += f"fd=os.open({name!r},os.O_WRONLY|os.O_CREAT|os.O_EXCL,{mode})\nwith os.fdopen(fd,'wb') as s: s.write(raw)\n"
        program += f"Path({name!r}).chmod({mode})\n"
    # Keep Docker's selected entrypoint path and upstream non-root access intact.
    program += "os.replace('/zentral/database-role-entrypoint.py','/zentral/docker-entrypoint.py')\n"
    program += f"print('Original database role module SHA256: {hashlib.sha256(module).hexdigest()}')\n"
    program += f"print('Database role entrypoint SHA256: {OUTPUT}')\n"
    return program
