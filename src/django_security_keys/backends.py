"""
This backend allows password-less authentication using
a security key device.

It is important that it comes before any other authentication
backends in the AUTHENTICATION_BACKENDS setting.
"""

from __future__ import annotations

from typing import Any

from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.models import User
from django.core.handlers.wsgi import WSGIRequest

from django_security_keys.models import SecurityKey


class PasswordlessAuthenticationBackend(ModelBackend):

    """
    Password-less authentication through webauthn
    """

    def authenticate(
        self,
        request: WSGIRequest,
        username: str | None = None,
        password: str | None = None,
        **kwargs: Any,
    ) -> User | None:
        # request can be None, for example in test environments

        if not request:
            return

        # clean up last used passwordless key

        try:
            del request.session["webauthn_passwordless"]
        except KeyError:
            pass

        credential = kwargs.get("u2f_credential")

        # no username supplied, abort password-less login silently
        # normal login process will raise required-field error
        # on username

        if not username or not credential:
            return

        has_credentials = SecurityKey.credentials(
            username, request.session, for_login=True
        )

        # no credential supplied

        if not has_credentials:
            return

        # verify password-less login
        try:
            key = SecurityKey.verify_authentication(
                username, request.session, credential, for_login=True
            )
            request.session["webauthn_passwordless"] = key.id
            return key.user
        except Exception:
            raise
