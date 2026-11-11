from __future__ import annotations

import json
import logging
from typing import Any

import django.forms as forms
from django.core.exceptions import ValidationError
from django.core.handlers.wsgi import WSGIRequest
from django.utils.translation import gettext as _
from django_otp import match_token
from webauthn.helpers.exceptions import (
    InvalidAuthenticationResponse,
    WebAuthnException,
)

from django_security_keys.models import SecurityKey

logger = logging.getLogger(__name__)


class DisableForm(forms.Form):
    """
    Form for disabling two-factor authentication.
    Requires either TOTP token, backup token, or security key credential for verification.
    """

    understand = forms.BooleanField(label=_("Yes, I am sure"))
    otp_token = forms.CharField(
        max_length=16,
        required=False,
        label=_("Authentication Code"),
        help_text=_("Enter your TOTP code, or your backup token"),
    )
    credential = forms.CharField(widget=forms.HiddenInput(), required=False)

    def __init__(
        self,
        request: WSGIRequest | None = None,
        user: Any | None = None,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        self.request = request
        self.user = user
        super().__init__(*args, **kwargs)

    def clean(self):
        super().clean()
        cleaned_data = self.cleaned_data

        if not cleaned_data.get("understand"):
            raise ValidationError(_("You must confirm you understand the risks"))

        # Check if user has provided either TOTP token or security key credential
        otp_token = cleaned_data.get("otp_token")
        credential = cleaned_data.get("credential")

        if not otp_token and not credential:
            raise ValidationError(
                _(
                    "You must verify with your authentication code, backup token, or security key"
                )
            )

        # Try TOTP verification first if token is provided
        if otp_token:
            device = match_token(self.user, otp_token)
            if device:
                return cleaned_data

        # Try security key verification if credential is provided
        if credential:
            try:
                SecurityKey.verify_authentication(
                    self.user.username, self.request.session, credential
                )
                return cleaned_data
            except (
                InvalidAuthenticationResponse,
                WebAuthnException,
                ValueError,
            ) as exc:
                logger.warning(
                    "Security key verification failed for user %s during 2FA disable: %s",
                    self.user.username,
                    exc,
                    exc_info=True,
                )

        # If reach here, verification failed
        raise ValidationError(
            _(
                "Invalid authentication code, backup token, or security key verification failed"
            )
        )


class PasswordConfirmationForm(forms.Form):
    """
    Form for confirming user's password before enabling 2FA.
    This adds a security layer to prevent unauthorized 2FA activation.
    """

    password = forms.CharField(
        widget=forms.PasswordInput(attrs={"autocomplete": "current-password"}),
        label=_("Current Password"),
    )

    def __init__(
        self,
        request: WSGIRequest | None = None,
        user: Any | None = None,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        self.request = request
        self.user = user
        super().__init__(*args, **kwargs)

    def clean_password(self):
        password = self.cleaned_data.get("password")
        if not password:
            raise ValidationError(_("Password is required."))

        if not self.user.check_password(password):
            raise ValidationError(_("Incorrect password. Please try again."))

        return password


class SecurityKeyDeviceValidation(forms.Form):
    credential = forms.CharField(widget=forms.HiddenInput())
    credential.widget.attrs.update({"type": "hidden"})

    def __init__(
        self,
        request: WSGIRequest | None = None,
        device: Any | None = None,
        passkey_credential_id: str | None = None,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        self.request = request
        self.device = device
        # ID of the credential that was used for passkey login in this session.
        # Used to reject POST-tampered submissions of the same credential as 2FA.
        self.passkey_credential_id = passkey_credential_id
        super().__init__(*args, **kwargs)

    def clean(self):
        super().clean()

        if self.device.authenticated:
            return self.cleaned_data

        credential = self.cleaned_data["credential"]

        # Reject the credential that was already used for passkey authentication.
        # The WebAuthn challenge mismatch would catch it too, but this is explicit.
        if self.passkey_credential_id:
            try:
                submitted_id = json.loads(credential).get("id")
            except (ValueError, KeyError):
                submitted_id = None
            if submitted_id and submitted_id == self.passkey_credential_id:
                raise ValidationError(
                    _("The passkey used for login cannot be used as a second factor.")
                )

        try:
            SecurityKey.verify_authentication(
                self.device.user.username, self.request.session, credential
            )
            self.device.authenticated = True
        except (InvalidAuthenticationResponse, WebAuthnException, ValueError) as exc:
            logger.warning(
                "Security key authentication failed for user %s: %s",
                self.device.user.username,
                exc,
                exc_info=True,
            )
            raise ValidationError(_("Security key authentication failed")) from exc

        return self.cleaned_data
