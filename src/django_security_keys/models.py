"""
Allows for passwordless login as well as using FIDO U2F for 2FA through django-two-factor.

2FA integration is handled by extending a custom django-two-factor device.

The Web Authentication API (also known as WebAuthn) is a specification written by the W3C and FIDO, with the participation of Google, Mozilla, Microsoft, Yubico, and others. The API allows servers to register and authenticate users using public key cryptography instead of a password.

Ref: https://webauthn.io/
Ref: https://webauthn.guide/#webauthn-api
Ref: https://w3c.github.io/webauthn
Ref: https://github.com/duo-labs/py_webauthn
"""

from __future__ import annotations

import secrets
from typing import Any

import webauthn
from django.conf import settings
from django.contrib.auth.models import User
from django.contrib.sessions.backends.db import SessionStore
from django.db import models
from django.utils.functional import SimpleLazyObject
from django.utils.translation import gettext_lazy as _
from django_otp.models import Device, ThrottlingMixin
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
from webauthn.helpers.structs import (
    AuthenticationCredential,
    PublicKeyCredentialDescriptor,
    RegistrationCredential,
)


class UserHandle(models.Model):

    """
    Unique identifier used to map users to their webauthn security keys

    Webauthn specifications recommend a unqiue set of 64 bytes for this value

    Ref: https://w3c.github.io/webauthn/#sctn-user-handle-privacy
    """

    user = models.OneToOneField(
        to=settings.AUTH_USER_MODEL,
        primary_key=True,
        related_name="webauthn_user_handle",
        on_delete=models.CASCADE,
    )

    handle = models.CharField(
        max_length=255,
        null=True,
        blank=True,
        help_text=_(
            "Unqiue user handle to be used to map users to their Webauthn credentials, only set if user has registered one or more security keys. Will be unique random 64 bytes"
        ),
        db_index=True,
        unique=True,
    )

    class Meta:
        db_table = "security_keys_user_handle"
        verbose_name = _("Webauthn User Handle")
        verbose_name_plural = _("Webauthn User Handles")

    @classmethod
    def require_for_user(cls, user: User | SimpleLazyObject) -> UserHandle:
        """
        Requires a user handle for the user, will create it if it does not exist

        Arguments:

        - user (`str`): django User instance

        Returns:

        - `UserHandle` instance
        """

        try:
            return user.webauthn_user_handle
        except UserHandle.DoesNotExist:
            pass

        handle = secrets.token_urlsafe(32)
        max_tries = 1000
        tries = 0

        while cls.objects.filter(handle=handle).exists():
            handle = secrets.token_urlsafe(32)
            if tries >= max_tries:
                raise ValueError(
                    _("Unable to generate unique user handle for webauthn")
                )
            tries += 1

        return cls.objects.create(user=user, handle=handle)


class SecurityKey(models.Model):

    """
    Describes a Webauthn (U2F) SecurityKey be used for passwordless
    login or 2FA

    2FA is handled through SecurityKeyDevice which allows integration
    of Webauthn security keys as a 2FA option for django_two_factor
    """

    class Meta:
        db_table = "security_keys_security_key"
        verbose_name = _("Webauthn Security Key")
        verbose_name_plural = _("Webauthn Security Keys")

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        related_name="webauthn_security_keys",
        on_delete=models.CASCADE,
    )

    name = models.CharField(max_length=255, null=True, help_text=_("Security key name"))
    credential_id = models.CharField(max_length=255, unique=True, db_index=True)
    credential_public_key = models.TextField()
    sign_count = models.PositiveIntegerField(default=0)
    attestation = models.TextField(
        null=True, blank=True, help_text=_("Attestation information")
    )

    type = models.CharField(max_length=64)
    passwordless_login = models.BooleanField(
        default=False, help_text=_("User has enabled this key for passwordless login")
    )

    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)

    @classmethod
    def set_challenge(cls, session: SessionStore, challenge: bytes) -> None:
        """
        Sets a webauthn challenge used for key registration or authentication
        on the session.

        This does NOT generate a challenge.

        Arguments:

        - session: django request session
        - challenge (`bytes`): byte string
        """
        session["webauthn_challenge"] = bytes_to_base64url(challenge)

    @classmethod
    def get_challenge(cls, session: SessionStore) -> bytes:
        """
        Retrives the webauthn challenge for the specified session

        Arguments:

        - session: dango request session

        Returns:

        - `bytes` challenge string
        """

        return base64url_to_bytes(session["webauthn_challenge"])

    @classmethod
    def clear_challenge(cls, session: SessionStore) -> None:
        """
        Removes the webauthn challenge from the specified session

        Arguments:

        - session: django request session
        """

        try:
            del session["webauthn_challenge"]
        except KeyError:
            pass

    @classmethod
    def generate_registration(cls, user: User, session: SessionStore) -> str:
        """
        Generate key registration options to be passed to
        navigator.credentials.create.

        Arguments:

        - user (`User`): django user instance
        - session: django request session

        Returns:

        - `str` JSON string
        """

        opts = webauthn.generate_registration_options(
            rp_id=settings.WEBAUTHN_RP_ID,
            rp_name=settings.WEBAUTHN_RP_NAME,
            user_id=UserHandle.require_for_user(user).handle,
            user_name=user.username,
            attestation=getattr(settings, "WEBAUTHN_ATTESTATION", "none"),
        )

        cls.set_challenge(session, opts.challenge)

        return webauthn.options_to_json(opts)

    @classmethod
    def verify_registration(
        cls, user: User, session: SessionStore, raw_credential: str, **kwargs: Any
    ) -> SecurityKey:
        """
        Verifies key registration and creates the SecurityKey instance
        on successful validation.

        Will also create a SecurityKeyDevice instance for the user if
        they do not have one yet.

        Arguments:

        - user (`User`): django user instance
        - session: django request session
        - raw_credential (`str`): JSON formatted credential as returned
          by navigator.credentials.create
        - name (`str`="main"): nick name for the key
        - passwordless_login (`bool`=False): enable the key for password-less
          login

        Returns:

        - `SecurityKey`: security key instance
        """

        # retrieve webauthn challenge from request session

        try:
            challenge = cls.get_challenge(session)
        except KeyError:
            raise ValueError(_("Invalid webauthn challenge"))

        # parse credential

        credential = RegistrationCredential.parse_raw(raw_credential)

        # client_data = parse_client_data_json(credential.response.client_data_json)

        # verify the credentials

        verified_registration = webauthn.verify_registration_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=settings.WEBAUTHN_RP_ID,
            expected_origin=settings.WEBAUTHN_ORIGIN,
        )

        # challenge clean up
        cls.clear_challenge(session)

        # create security key
        key = cls.objects.create(
            user=user,
            credential_id=bytes_to_base64url(verified_registration.credential_id),
            credential_public_key=bytes_to_base64url(
                verified_registration.credential_public_key
            ),
            sign_count=verified_registration.sign_count,
            name=kwargs.get("name", "main"),
            passwordless_login=kwargs.get("passwordless_login", False),
            attestation=bytes_to_base64url(verified_registration.attestation_object),
            type="security-key",
        )

        # create django-two-factor device for security keys so
        # they become in option in the 2FA process.

        SecurityKeyDevice.require_for_user(user)
        return key

    @classmethod
    def clear_session(cls, session: SessionStore):
        """
        Cleans up webauthn data for session

        Arguments:

        - session: request session
        """

        try:
            del session["webauthn_passwordless"]
        except KeyError:
            pass

    @classmethod
    def credentials(
        cls, username: User | str, session: SessionStore, for_login: bool = False
    ) -> list[PublicKeyCredentialDescriptor]:
        """
        Returns a list of credentials for the specified username

        Arguments:

        - username (`str`)
        - session: django request session
        - for_login (`bool`=False): if True indicates that the
          credentials are to be used for password-less login.

          if False indicates that the credentials are to be used
          as a two-factor step

        Returns:

        - `list<PublicKeyCredentialDescriptor>`
        """

        qset = cls.objects.filter(user__username=username)

        # if a security key was used for passwordless auth
        # it should not be available for two factor auth

        pl_key_id = session.get("webauthn_passwordless")
        if pl_key_id and not for_login:
            qset = qset.exclude(id=pl_key_id)

        # if to be used for password-less login, exclude
        # credentials that are not enabled for that.
        if for_login:
            qset = qset.filter(passwordless_login=True)

        return [
            PublicKeyCredentialDescriptor(
                type="public-key",
                id=base64url_to_bytes(key.credential_id),
            )
            for key in qset
        ]

    @classmethod
    def generate_authentication(
        cls, username: User | str, session: SessionStore, for_login: bool = False
    ) -> str:
        """
        Generates webauthn authentication options to be passed to
        `navagitor.credentials.get`

        Arguments:

        - username (`str`)
        - session: django request session
        - for_login: (`bool`=False): authentication options for password-less
          login

        Returns:

        - `str` JSON
        """

        opts = webauthn.generate_authentication_options(
            rp_id=settings.WEBAUTHN_RP_ID,
            allow_credentials=cls.credentials(username, session, for_login=for_login),
        )

        cls.set_challenge(session, opts.challenge)

        return webauthn.options_to_json(opts)

    @classmethod
    def verify_authentication(
        cls,
        username: str,
        session: SessionStore,
        raw_credential: str,
        for_login: bool = False,
    ) -> SecurityKey:
        """
        Verify the webauthn authentication

        Arguments:

        - username (`str`)
        - session: django request session
        - raw_credentials (`str`): JSON formatted PublicKeyCredential as returned
          from `navigator.credentials.get`
        - for_login: (`bool`=False): verify a password-less login attempt

        Returns:

        - `SecurityKey`: security key instance
        """

        # get webauthn challenge from session

        try:
            challenge = cls.get_challenge(session)
        except KeyError:
            raise ValueError(_("Invalid webauthn challenge"))

        # parse credential

        credential = AuthenticationCredential.parse_raw(raw_credential)

        try:
            key = cls.objects.get(credential_id=credential.id)
        except SecurityKey.DoesNotExist:
            raise ValueError(_("Security key authentication failed"))

        if for_login and not key.passwordless_login:
            raise ValueError(_("Security key not enabled for password-less login"))

        # verify authentication

        verified_authentication = webauthn.verify_authentication_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=settings.WEBAUTHN_RP_ID,
            expected_origin=settings.WEBAUTHN_ORIGIN,
            credential_public_key=base64url_to_bytes(key.credential_public_key),
            credential_current_sign_count=key.sign_count,
        )

        # clear challenge

        cls.clear_challenge(session)

        # update sign count

        key.sign_count = verified_authentication.new_sign_count
        key.save()

        return key


class SecurityKeyDevice(ThrottlingMixin, Device):
    """
    django-two-factor security key device

    This is NOT per key, a user needs to have one instance of this
    for their security keys to be available as an option for 2FA
    """

    class Meta:
        db_table = "security_keys_2fa_device"
        verbose_name = _("Webauthn Security Key 2FA Device")
        verbose_name_plural = _("Webauthn Security Key 2FA Devices")

    @classmethod
    def require_for_user(cls, user: User) -> SecurityKeyDevice:
        try:
            return cls.objects.get(user=user)
        except cls.DoesNotExist:
            return cls.objects.create(user=user, name="security-keys")

    @property
    def method(self) -> str:
        return "security-key"

    @property
    def authenticated(self):
        return getattr(self, "_authenticated", False)

    @authenticated.setter
    def authenticated(self, value):
        self._authenticated = value
