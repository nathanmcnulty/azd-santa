"""Original Unlicense local-operator bootstrap/recovery for the pinned core build.

Recovery authority is privileged host/container management, not a browser bypass.
No dependencies or Django models are imported while settings are initializing.
"""
import json
import os
from pathlib import Path
import secrets
import time
from urllib.parse import urlsplit

RESET_SECONDS = 600


class AccessError(RuntimeError):
    pass


def validate_request(mode, username, email, reason):
    if mode not in ('bootstrap', 'recover'):
        raise AccessError('Choose bootstrap or recover.')
    if (not isinstance(username, str) or not username or username != username.strip()
            or len(username) > 150 or not isinstance(email, str)
            or email != email.strip() or not email or len(email) > 254):
        raise AccessError('Provide the exact username and email.')
    if (not isinstance(reason, str) or not reason.strip() or len(reason) > 256
            or any(ord(char) < 32 for char in reason)):
        raise AccessError('Provide a single-line reason of at most 256 characters; never include secrets.')


def reserve_output(value):
    path = Path(value)
    if not path.is_absolute() or path.parent.resolve(strict=True) != path.parent:
        raise AccessError('Choose an absolute path in an existing non-symlink directory.')
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        if os.name != 'nt':
            os.fchmod(descriptor, 0o600)
    except Exception:
        os.close(descriptor)
        raise
    return descriptor


def apply_access(mode, username, email, reason, output, *, recipient_public_key=None,
                 context_sha256=None, sealed_stdout=False):
    from django.conf import settings
    from django.contrib.contenttypes.models import ContentType
    from django.core.exceptions import ValidationError
    from django.core.validators import validate_email
    from django.db import transaction
    from accounts.models import User, APIToken, OIDCAPITokenIssuer
    from accounts.password_reset import handler
    from zentral.core.events.base import AuditEvent

    validate_request(mode, username, email, reason)
    try:
        validate_email(email)
        User._meta.get_field('username').clean(username, None)
    except ValidationError:
        raise AccessError('Provide a valid exact username and email identity.') from None
    if settings.PASSWORD_RESET_TIMEOUT != RESET_SECONDS:
        raise AccessError('The reviewed ten-minute reset policy is not installed.')
    recipient = None
    if recipient_public_key is not None:
        try:
            from zentral.conf import api_base_url
            from azd_santa_sealed_setup import prepare_recipient
            recipient = prepare_recipient(recipient_public_key, context_sha256, mode,
                                          username, email, api_base_url())
        except Exception:
            raise AccessError('Recipient key/context/origin validation failed before user security changes.') from None
    elif context_sha256 is not None or sealed_stdout:
        raise AccessError('Sealed export requires an explicit recipient public key and context digest.')
    phase = 'unconfirmed'
    descriptor = reserve_output(output)
    with os.fdopen(descriptor, 'w', encoding='utf-8') as stream:
        try:
            # A durable outer transaction makes commit/partial-output reporting
            # explicit. The existing ContentType row serializes simultaneous
            # bootstrap commands without SQL snippets or a new schema/model.
            with transaction.atomic(durable=True):
                ContentType.objects.select_for_update().get(
                    app_label=User._meta.app_label, model=User._meta.model_name)
                if mode == 'bootstrap':
                    if User.objects.filter(is_service_account=False).exists():
                        raise AccessError('Bootstrap requires no human accounts, including inactive or remote humans; use targeted recovery.')
                    if User.objects.filter(username__iexact=username).exists() or User.objects.filter(email__iexact=email).exists():
                        raise AccessError('Bootstrap identity conflicts with an existing account.')
                    user = User.objects.create_user(username=username, email=email,
                                                    is_superuser=True, is_staff=False)
                    action = AuditEvent.Action.CREATED
                    previous = None
                else:
                    user = User.objects.select_for_update().filter(username=username).first()
                    if user is None or user.email != email:
                        raise AccessError('Exact target username and email did not match.')
                    if not user.is_active or user.is_remote or user.is_service_account:
                        raise AccessError('Recovery requires an active local human; it never activates or converts accounts.')
                    action = AuditEvent.Action.UPDATED
                    previous = user.serialize_for_event()
                removed = dict(totp=user.usertotp_set.count(), webauthn=user.userwebauthn_set.count(),
                               human_tokens=APIToken.objects.filter(user=user).count(),
                               human_oidc_issuers=OIDCAPITokenIssuer.objects.filter(user=user).count())
                user.set_password(secrets.token_urlsafe(64))  # unknown, never exported
                user.save()
                user.usertotp_set.all().delete()
                user.userwebauthn_set.all().delete()
                APIToken.objects.filter(user=user).delete()
                OIDCAPITokenIssuer.objects.filter(user=user).delete()
                setup_url = handler.generate_password_reset_url(user)
                parsed = urlsplit(setup_url)
                if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
                    raise AccessError('A configured HTTPS setup origin is required.')
                event = AuditEvent.build(user, action, prev_value=previous)
                event.payload['operator_access'] = dict(
                    mode=mode, reason=reason, removed=removed,
                    authority='privileged host management; no browser actor asserted')
                artifact = dict(scope='private-local-operator-setup', mode=mode,
                                target=dict(pk=user.pk, username=user.username, email=user.email),
                                reason=reason, removed=removed, setup_url=setup_url,
                                expires_at_unix=time.time() + RESET_SECONDS,
                                audit='submission not delivery proof',
                                session_invalidation='password/auth-hash invalidation; session rows are not purged')
                # Encrypt/size-check while rollback is still possible. Only the
                # sealed artifact is ever written when a recipient was supplied.
                output_artifact = recipient.seal(artifact) if recipient else artifact
            phase = 'committed'
            json.dump(output_artifact, stream, separators=(',', ':') if recipient else None,
                      indent=None if recipient else 2)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
            phase = 'artifact-written'
            event.post()
            result = dict(target=artifact['target'], removed=removed)
            if sealed_stdout:
                result['sealed'] = output_artifact
            return result
        except AccessError:
            raise
        except Exception:
            if phase == 'artifact-written':
                raise AccessError('Access reset committed and private setup artifact written; audit submission failed. Inspect locally.') from None
            if phase == 'committed':
                raise AccessError('Access reset committed but setup artifact write failed. Inspect target state; reissue targeted recovery to a new absent path.') from None
            raise AccessError('No confirmed access commit; reserved artifact retained. Inspect target state before retrying.') from None


def command_class():
    from django.core.management.base import BaseCommand, CommandError
    from zentral.core.queues import queues

    class Command(BaseCommand):
        help = 'Bootstrap the first human admin or recover one exact local human; setup link is written privately, never printed.'

        def add_arguments(self, parser):
            parser.add_argument('mode', choices=('bootstrap', 'recover'))
            parser.add_argument('--username', required=True)
            parser.add_argument('--email', required=True)
            parser.add_argument('--reason', required=True)
            parser.add_argument('--output', required=True, help='Absent absolute private artifact path')
            parser.add_argument('--recipient-public-key', help='Base64 DER SubjectPublicKeyInfo RSA-3072 recipient public key')
            parser.add_argument('--context-sha256', help='Caller-verified selected deployment/request binding digest')
            parser.add_argument('--sealed-stdout', action='store_true', help='Emit only the bounded sealed envelope after success')

        def handle(self, *args, **options):
            completed = False
            try:
                result = apply_access(*(options[key] for key in ('mode', 'username', 'email', 'reason', 'output')),
                                      recipient_public_key=options.get('recipient_public_key'),
                                      context_sha256=options.get('context_sha256'), sealed_stdout=options.get('sealed_stdout', False))
                completed = True
            except AccessError as error:
                raise CommandError(str(error)) from None
            except OSError:
                raise CommandError('Private output could not be reserved; no setup credential is printed.') from None
            finally:
                try:
                    queues.stop()
                except Exception:
                    status = 'Access committed and private setup artifact written' if completed else 'Access state requires inspection'
                    raise CommandError(status + '; audit flush failed. Inspect locally.') from None
            self.stdout.write('Operator access committed; private setup artifact written; audit submitted (not delivery proof).')
            if options.get('sealed_stdout'):
                # Keep this last and bounded for Azure Run Command's output tail.
                self.stdout.write('SANTA_SEALED_SETUP_JSON:' + json.dumps(result['sealed'], separators=(',', ':')))

    return Command


def reset_confirm_view():
    # URLconf loads this factory after Django setup. Importing auth.views at
    # policy/settings import time would prematurely resolve the user model.
    from django.contrib.auth.views import PasswordResetConfirmView
    from django.db import transaction

    class LockedResetConfirmView(PasswordResetConfirmView):
        post_reset_login = False

        def dispatch(self, *args, **kwargs):
            with transaction.atomic():
                return super().dispatch(*args, **kwargs)

        def get_user(self, uidb64):
            user = super().get_user(uidb64)
            if user is None:
                return None
            # Refetch AFTER acquiring the row lock. Concurrent reset/recovery
            # must validate the new password hash rather than a stale instance.
            try:
                user = type(user).objects.select_for_update().get(pk=user.pk)
            except type(user).DoesNotExist:
                return None
            if not user.is_active or user.is_remote or user.is_service_account:
                return None
            return user

    return LockedResetConfirmView.as_view()
