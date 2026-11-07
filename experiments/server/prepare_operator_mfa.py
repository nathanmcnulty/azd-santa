"""Hash-bound core integration for the original operator MFA policy module."""
import ast
import base64
import hashlib
from pathlib import Path

INPUTS = {
    'server/server/settings.py': '1f302e91ed35a170e1580a8c79c218bb812c6efc09f7850bb41392f9ce6bd2b1',
    'server/accounts/views/auth.py': 'a947b0f52da74c30909164587f05d8b0a87e2a98a136545971108007f54eeccf',
    'server/accounts/forms.py': 'd6397a2d4238f57d9eeb22cdc87f2a0d7b176bf93516e2073a15ba22d9cf6eec',
    'server/accounts/views/user.py': 'ffe6348faaf2edf6436e7bab2e8d346586eabb5bbb1893889035e1c566a625a4',
    'server/accounts/middleware.py': '0d0e06858dbd87c11bd161d2d03145c54840d1dc5b40e55995897f98c886c2ec',
    'server/accounts/api_authentication.py': '65c4ce3ee597279b328da32420424e18d58be800d682d10f56caa0f73981140c',
}
OUTPUTS = {
    'server/server/settings.py': '8569481c18962c007698dc4492c2ea402eb49ec2fb1d44249274866642fcfb68',
    'server/accounts/views/auth.py': 'c5b6d224a95c3c0ab89c12b24f1971d18af27548ea67461f3598721a14fc0c5c',
    'server/accounts/forms.py': 'ef4adc2ea64d7f92bb9b1683082baa4f946ab1d21867c5e0ac10496db192bc6a',
    'server/accounts/views/user.py': 'cdf2706180277a9eee695cf1a6aca561b2f941bec0dd7b7d690085590d19440c',
    'server/accounts/middleware.py': '0728dff4626a67bec29895bd1a1037e5c4f720f30c8ef436219be39a25c8885a',
    'server/accounts/api_authentication.py': '736bc55c85d5d836e8bd64f797dafd81c0993826528ba35d3cc6b6acc1e0fadc',
}
NOTICE = '# Modified by azd-santa: integrate mandatory local operator MFA policy.\n'

PATCHES = {
    'server/server/settings.py': [(
        "ROOT_URLCONF = 'server.urls'",
        "from azd_santa_operator import install_policy as _azd_install_policy\n"
        "_azd_install_policy(globals())\n\nROOT_URLCONF = 'server.urls'",
    )],
    'server/accounts/views/auth.py': [
        ('from accounts.events import post_failed_verification_event',
         'from azd_santa_operator import begin_enrollment, prepare_mfa, complete_mfa, challenge_nonce, LOCAL_BACKEND\nfrom accounts.events import post_failed_verification_event'),
        ('token = signing.dumps({"auth_backend": user.backend,',
         'token = signing.dumps({"auth_backend": user.backend,\n                                       "azd_auth_hash": user.get_session_auth_hash(),\n                                       "azd_nonce": challenge_nonce(),'),
        ('        self.request.session["mfa_authenticated"] = True\n',
         '        verification_token = self.request.session["verification_token"]\n'
         '        try:\n'
         '            accepted_user, proof = prepare_mfa(self.request, form.user, form.verified_device, form.cleaned_data.get("verification_code"), verification_token=verification_token)\n'
         '        except PermissionDenied:\n'
         '            post_failed_verification_event(self.request, form)\n'
         '            raise\n'
         '        self.request.session["mfa_authenticated"] = True\n'),
        ('                auth_login(request, form.get_user())\n',
         '                auth_login(request, form.get_user())\n                begin_enrollment(request, form.get_user())\n'),
        ('        auth_login(self.request, form.user)  # form.user has the backend (carried by the token from the login view)\n',
         '        auth_login(self.request, accepted_user, backend=LOCAL_BACKEND)\n'
         '        complete_mfa(self.request, proof)\n'),
    ],
    'server/accounts/forms.py': [
        ('        self.user = User.objects.get(pk=token_data["user_id"])',
         '        self.user = User.objects.select_for_update().get(pk=token_data["user_id"])  # lock user before factor verification/recovery'),
        ('class AddTOTPForm(forms.Form):',
         'from azd_santa_operator import enrollment_seed, check_seed\n\n\nclass AddTOTPForm(forms.Form):'),
        ('        self.user = kwargs.pop("user")\n        super().__init__(*args, **kwargs)\n        if self.is_bound:\n            # verification code error',
         '        self.user = kwargs.pop("user")\n        self.session = kwargs.pop("session")\n        super().__init__(*args, **kwargs)\n        if self.is_bound:\n            # verification code error'),
        ('            self.fields["secret"].initial = pyotp.random_base32()',
         '            self.fields["secret"].initial = enrollment_seed(self.session, self.user)'),
        ('        if self.is_bound:\n            return self.data["secret"]\n        else:\n            return self.fields["secret"].initial',
         '        return enrollment_seed(self.session, self.user)'),
        ('        secret = self.cleaned_data["secret"]\n        verification_code = self.cleaned_data["verification_code"]\n        totp = pyotp.totp.TOTP(secret)',
         '        secret = self.cleaned_data.get("secret")\n        verification_code = self.cleaned_data.get("verification_code")\n'
         '        if not secret or not verification_code:\n            return self.cleaned_data\n'
         '        if not check_seed(self.session, self.user, secret):\n            raise forms.ValidationError("Restart verification setup; the setup secret changed.")\n'
         '        totp = pyotp.totp.TOTP(secret)'),
        ('                if verification_device.verify(verification_code):\n                    break',
         '                if verification_device.verify(verification_code):\n                    self.verified_device = verification_device\n                    break'),
        ('        device.sign_count = verification.new_sign_count\n        device.save()\n',
         '        device.sign_count = verification.new_sign_count\n        device.save()\n        self.verified_device = device\n'),
    ],
    'server/accounts/views/user.py': [(
        '    template_name = "accounts/add_totp.html"\n    form_class = AddTOTPForm\n    success_url = reverse_lazy("accounts:verification_devices")\n\n'
        '    def get_form_kwargs(self):\n        kwargs = super().get_form_kwargs()\n        kwargs["user"] = self.request.user\n        return kwargs',
        '    template_name = "accounts/add_totp.html"\n    form_class = AddTOTPForm\n    success_url = reverse_lazy("accounts:verification_devices")\n\n'
        '    def get_form_kwargs(self):\n        kwargs = super().get_form_kwargs()\n        kwargs["user"] = self.request.user\n        kwargs["session"] = self.request.session\n        return kwargs',
    )],
    'server/accounts/middleware.py': [(
        '    ok_url = set([password_change_url,',
        '    ok_url = set([reverse("accounts:add_totp"), password_change_url,',
    )],
    'server/accounts/api_authentication.py': [(
        '        return (token.user, token)',
        '        if not token.user.is_service_account:\n'
        '            raise exceptions.AuthenticationFailed(_("Use an MFA operator session; human API tokens are disabled."))\n\n'
        '        return (token.user, token)',
    )],
}


def transform(path, raw):
    if path not in INPUTS or hashlib.sha256(raw).hexdigest() != INPUTS[path]:
        raise ValueError('Unreviewed operator MFA input: ' + path)
    text = raw.decode('utf-8')
    for old, new in PATCHES[path]:
        if text.count(old) != 1:
            raise ValueError('Operator MFA source shape changed: ' + path)
        text = text.replace(old, new, 1)
    result = (NOTICE + text).encode('utf-8')
    ast.parse(result, filename=path)
    return result


def docker_program(source_root, module_path):
    """Validate archive inputs, then generate a bounded, independently checked layer."""
    module = Path(module_path).read_bytes().replace(b'\r\n', b'\n')
    ast.parse(module, filename='azd_santa_operator.py')
    if set(OUTPUTS) != set(INPUTS):
        raise ValueError('Reviewed operator MFA output hashes are incomplete')
    for path, expected in OUTPUTS.items():
        result = transform(path, (Path(source_root) / path).read_bytes())
        if hashlib.sha256(result).hexdigest() != expected:
            raise ValueError('Unreviewed operator MFA output: ' + path)
    # Code is ours; upstream content is only data, never executed here.
    program = (
        'import ast,base64,hashlib\nfrom pathlib import Path\n'
        f'inputs={INPUTS!r}\noutputs={OUTPUTS!r}\npatches={PATCHES!r}\nnotice={NOTICE!r}\n'
        'for name,expected in inputs.items():\n'
        "    path=Path('/zentral')/name\n    raw=path.read_bytes()\n"
        "    if hashlib.sha256(raw).hexdigest()!=expected: raise RuntimeError('MFA input mismatch: '+name)\n"
        "    text=raw.decode('utf-8')\n    for old,new in patches[name]:\n"
        "        if text.count(old)!=1: raise RuntimeError('MFA shape mismatch: '+name)\n"
        '        text=text.replace(old,new,1)\n'
        "    result=(notice+text).encode('utf-8')\n"
        "    if hashlib.sha256(result).hexdigest()!=outputs[name]: raise RuntimeError('MFA output mismatch: '+name)\n"
        '    ast.parse(result,filename=name)\n    path.write_bytes(result)\n'
        f"module=base64.b64decode({base64.b64encode(module).decode()!r})\n"
        f"if hashlib.sha256(module).hexdigest()!={hashlib.sha256(module).hexdigest()!r}: raise RuntimeError('MFA module mismatch')\n"
        "Path('/zentral/server/azd_santa_operator.py').write_bytes(module)\n"
        "command=Path('/zentral/server/accounts/management/commands/operator_security_store.py')\n"
        "with command.open('xb') as output:\n"
        "    output.write(b'# Original Unlicense security-store command.\\nfrom azd_santa_operator import security_store_command_class\\nCommand = security_store_command_class()\\n')\n"
        "command.chmod(0o644)\n"
    )
    return program, hashlib.sha256(module).hexdigest()
