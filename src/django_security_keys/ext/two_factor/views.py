from __future__ import annotations

import json
import logging
import time
from typing import Any

import two_factor.views
from django.conf import settings as dj_settings
from django.contrib.auth import authenticate
from django.contrib.auth import login as auth_login
from django.contrib.auth.forms import AuthenticationForm
from django.core.handlers.wsgi import WSGIRequest
from django.http.response import HttpResponseBase, HttpResponseRedirect
from django.shortcuts import redirect
from django.template.response import TemplateResponse
from django.utils.translation import gettext_lazy as _
from django.views.generic import FormView
from django_otp import devices_for_user
from django_otp.plugins.otp_email.models import EmailDevice
from webauthn.helpers import base64url_to_bytes
from webauthn.helpers.exceptions import WebAuthnException

from django_security_keys.ext.two_factor import forms
from django_security_keys.ext.two_factor.forms import (
    DisableForm,
    PasswordConfirmationForm,
    SecurityKeyDeviceValidation,
)
from django_security_keys.models import SecurityKey, SecurityKeyDevice, UserHandle

logger = logging.getLogger(__name__)


class SetupView(two_factor.views.SetupView):
    """
    Extended SetupView that requires password confirmation before enabling 2FA.
    This prevents unauthorized 2FA activation by attackers with session access.
    """

    PASSWORD_STEP = "password"

    form_list = (
        (PASSWORD_STEP, PasswordConfirmationForm),
    ) + two_factor.views.SetupView.form_list

    def get_form_kwargs(self, step=None):
        kwargs = super().get_form_kwargs(step)
        if step == self.PASSWORD_STEP:
            kwargs["request"] = self.request
            kwargs["user"] = self.request.user
        return kwargs

    def get_context_data(self, form, **kwargs):
        context = super().get_context_data(form, **kwargs)
        if self.steps.current == self.PASSWORD_STEP:
            context["cancel_url"] = "/"
        return context


class DisableView(two_factor.views.DisableView):
    """
    View for disabling two-factor authentication.
    Requires 2FA verification before allowing deactivation.
    """

    form_class = DisableForm

    def dispatch(self, *args: Any, **kwargs: Any) -> HttpResponseBase:
        self.success_url = "/"
        return FormView.dispatch(self, *args, **kwargs)

    def get_form_kwargs(self) -> dict[str, Any]:
        """Pass request and user to the form."""
        kwargs = super().get_form_kwargs()
        kwargs["request"] = self.request
        kwargs["user"] = self.request.user
        return kwargs

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add security key credentials to context for WebAuthn."""
        context = super().get_context_data(**kwargs)

        # Check if user has security keys
        user = self.request.user
        if user and SecurityKey.objects.filter(user=user).exists():
            context["has_security_keys"] = True
            # Generate authentication options for WebAuthn
            try:
                context["security_key_options"] = SecurityKey.generate_authentication(
                    user.username, self.request.session, for_login=False
                )
            except Exception:
                context["security_key_options"] = None

        # Check if user has email TOTP and automatically send code
        try:
            email_device = EmailDevice.objects.get(user=user, confirmed=True)
            # Only send on GET requests (when page is first loaded), not on POST
            if self.request.method == "GET":
                email_device.generate_challenge()
                context["email_token_sent"] = True
            context["has_email_device"] = True
        except EmailDevice.DoesNotExist:
            context["has_email_device"] = False
            context["email_token_sent"] = False

        return context

    def form_valid(self, form: DisableForm) -> HttpResponseRedirect:
        """Delete all 2FA devices after successful verification."""
        for device in devices_for_user(self.request.user):
            device.delete()
        return super().form_valid(form)


class LoginView(two_factor.views.LoginView):
    form_list = two_factor.views.LoginView.form_list + (
        ("security-key", forms.SecurityKeyDeviceValidation),
    )

    @property
    def disable_password_auth(self) -> bool:
        """If True, done() blocks login unless the user authenticated via passkey."""
        return False

    @property
    def disable_totp(self) -> bool:
        """If True, skip the token and backup-code steps on the non-passkey path."""
        return False

    @property
    def require_passkey_mfa(self) -> bool:
        """If True, require MFA even after a successful passkey authentication."""
        return False

    def has_token_step(self) -> bool:
        if self.storage.data.get("passkey_authenticated"):
            # Passkey auth normally satisfies 2FA, but can still require MFA on top.
            # If MFA is required but TOTP is disallowed, skip the token step
            # (the user cannot be asked for a method their org has disabled).
            if self.require_passkey_mfa and not self.disable_totp:
                return two_factor.views.LoginView.has_token_step(self)
            return False

        # Non-passkey path: honour TOTP disable flag.
        if self.disable_totp:
            return False

        return two_factor.views.LoginView.has_token_step(self)

    def has_backup_step(self) -> bool:
        if self.storage.data.get("passkey_authenticated"):
            # Same logic as has_token_step.
            if self.require_passkey_mfa and not self.disable_totp:
                return two_factor.views.LoginView.has_backup_step(self)
            return False

        # Non-passkey path: backup codes are tied to TOTP, disable together.
        if self.disable_totp:
            return False

        return two_factor.views.LoginView.has_backup_step(self)

    def get_passkey_required_error(self) -> str:
        """
        Return the error message stored in the session when password login is
        blocked by disable_password_auth.

        Override in subclasses to provide application-specific wording.
        Must return a plain str (not a lazy translation proxy) because the
        session backend serializes session data with json.dumps().
        """
        return str(_("Passkey authentication is required to log in."))

    def get_mfa_incomplete_redirect(self):
        """
        Called when require_passkey_mfa is True but MFA was not completed
        (either because the user has no TOTP device, or because disable_totp
        prevented the step from being shown).

        Return a URL string to redirect the user (e.g. to MFA setup), or None
        to let the login proceed anyway.

        Override in subclasses to enforce the requirement. The default returns
        None for backwards compatibility.
        """
        return None

    def done(self, form_list, **kwargs):
        if self.disable_password_auth and not self.storage.data.get(
            "passkey_authenticated"
        ):
            self.request.session["passkey_required_error"] = (
                self.get_passkey_required_error()
            )
            self.storage.reset()
            return redirect(dj_settings.LOGIN_URL)

        if self.storage.data.get("passkey_authenticated") and self.require_passkey_mfa:
            done_forms = self.get_done_form_list()
            mfa_completed = (
                "token" in done_forms
                or "backup" in done_forms
                or "security-key" in done_forms
            )
            if not mfa_completed:
                url = self.get_mfa_incomplete_redirect()
                if url is not None:
                    user = self.get_user()
                    self.storage.reset()
                    # Log the user in so they can access the redirect target
                    # (e.g. the MFA setup page), which requires authentication.
                    auth_login(self.request, user)
                    return redirect(url)

        # Password path: if TOTP is disabled by policy and the user has no
        # security-key step to satisfy it, they would slip through without any
        # MFA challenge. Give the hook a chance to redirect them to setup.
        if not self.storage.data.get("passkey_authenticated") and self.disable_totp:
            done_forms = self.get_done_form_list()
            if "security-key" not in done_forms:
                url = self.get_mfa_incomplete_redirect()
                if url is not None:
                    user = self.get_user()
                    self.storage.reset()
                    auth_login(self.request, user)
                    return redirect(url)

        return super().done(form_list, **kwargs)

    def has_security_key_step(self) -> bool:
        if not self.get_user():
            return False

        if self.storage.data.get("passkey_authenticated"):
            # Passkey auth normally satisfies 2FA on its own.
            # When require_passkey_mfa is set, the user must still complete an
            # additional MFA step — a second (non-passkey) security key can
            # satisfy this requirement.
            if not self.require_passkey_mfa:
                return False
            # TOTP or backup code already satisfied the MFA requirement.
            if self.storage.get_step_data("token"):
                return False
            if self.storage.get_step_data("backup"):
                return False
            # credentials() with for_login=False returns only 2FA keys
            # (passkey_login=False), so the passkey-login key is already
            # excluded by the queryset filter. Explicitly filter out the
            # credential_id that was used for passkey login as a second
            # safety layer against edge cases.
            creds = SecurityKey.credentials(self.get_user().username)
            used_id = self.storage.data.get("passkey_credential_id")
            if used_id:
                try:
                    used_id_bytes = base64url_to_bytes(used_id)
                    creds = [c for c in creds if c.id != used_id_bytes]
                except Exception:
                    logger.warning(
                        "Failed to decode passkey_credential_id %r for user %s; "
                        "skipping explicit credential exclusion",
                        used_id,
                        self.get_user().username,
                    )
            return len(creds) > 0

        # Non-passkey path: skip if TOTP or backup already completed.
        if self.storage.get_step_data("token"):
            return False
        if self.storage.get_step_data("backup"):
            return False

        return len(SecurityKey.credentials(self.get_user().username)) > 0

    condition_dict = {
        "backup": has_backup_step,
        "token": has_token_step,
        "security-key": has_security_key_step,
    }

    def post(
        self, *args: Any, **kwargs: Any
    ) -> HttpResponseRedirect | TemplateResponse:
        request = self.request
        if not request.POST.get("auth-username"):
            attempt_passkey_auth = self.attempt_passkey_auth(request, **kwargs)
            if attempt_passkey_auth:
                return attempt_passkey_auth
        return super().post(*args, **kwargs)

    def attempt_passkey_auth(
        self, request: WSGIRequest, **kwargs: Any
    ) -> HttpResponseRedirect | None:
        """
        Prepares and attempts a passkey authentication
        using a security key credential.

        This requires that the auth-username and credential
        fields are set in the POST data.

        """

        if self.steps.current == "auth":
            try:
                credential = request.POST.get("credential")
                if not credential:
                    raise ValueError("No credential provided")
                try:
                    user_handle = base64url_to_bytes(
                        json.loads(credential)["response"]["userHandle"]
                    ).decode("utf-8")
                    username = UserHandle.objects.get(handle=user_handle).user.username
                except (
                    ValueError,
                    KeyError,
                    UserHandle.DoesNotExist,
                    WebAuthnException,
                ) as exc:
                    logger.warning("Failed to parse passkey credential: %s", exc)
                    raise ValueError(f"Failed login using passkey: {exc}") from exc
                # support passkey login using webauthn
                if username and credential:
                    user = authenticate(
                        request, username=username, u2f_credential=credential
                    )
                    if not user:
                        logger.warning(
                            "Passkey authentication failed for username: %s", username
                        )
                        raise ValueError("Failed login using passkey")
                    self.storage.reset()
                    self.storage.authenticated_user = user
                    self.storage.data["authentication_time"] = int(time.time())
                    self.storage.data["passkey_authenticated"] = True
                    # Record which credential was used so that the security-key
                    # MFA step can exclude it from the allowed candidates and
                    # reject it if submitted directly (POST-tampering defense).
                    self.storage.data["passkey_credential_id"] = json.loads(
                        credential
                    )["id"]
                    form = self.get_form(
                        data=self.request.POST, files=self.request.FILES
                    )
                    if self.steps.current == self.steps.last:
                        return self.render_done(form, **kwargs)
                    return self.render_next_step(form)

            except (ValueError, WebAuthnException) as exc:
                logger.info("Passkey authentication attempt failed: %s", exc)
                self.passkey_error = f"{exc}"
                return self.render_goto_step("auth")

        return None

    def get_context_data(
        self, form: AuthenticationForm | SecurityKeyDeviceValidation, **kwargs: Any
    ) -> dict[str, Any]:
        """
        If post request was rate limited the rate limit message
        needs to be communicated via the template context.
        """

        context = super().get_context_data(form, **kwargs)

        if "other_devices" in context:
            if self.has_security_key_step():
                context["other_devices"] += [self.get_security_key_device()]

        context["passkey_error"] = getattr(self, "passkey_error", None)

        if self.steps.current == "security-key":
            context["device"] = self.get_security_key_device()

        return context

    def get_security_key_device(self) -> SecurityKeyDevice | None:
        """
        Will return a device object representing a webauthn
        choice if the user has any webauthn devices set up
        """

        if hasattr(self, "_security_key_device"):
            return self._security_key_device

        user = self.get_user()

        if not user or not user.webauthn_security_keys.exists():
            return None

        device = SecurityKeyDevice.require_for_user(user)
        device.user = user

        self._security_key_device = device

        return device

    def get_device(self, step: str | None = None) -> SecurityKeyDevice:
        """
        Override this to can enable EmailDevice as a
        challenge device for one time passwords.
        """

        if not self.device_cache:
            challenge_device_id = self.request.POST.get("challenge_device", None)
            if challenge_device_id:
                # security key device
                device = self.get_security_key_device()
                if device and device.persistent_id == challenge_device_id:
                    self.device_cache = device
                    return self.device_cache

        return super().get_device(step=step)
