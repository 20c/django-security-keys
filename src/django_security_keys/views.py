from __future__ import annotations

import json
import logging
import traceback
from typing import Any

from django.conf import settings
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.core.handlers.wsgi import WSGIRequest
from django.db import transaction
from django.http import JsonResponse
from django.http.response import HttpResponse, HttpResponseRedirect
from django_otp import match_token
from django.shortcuts import redirect, render
from django.urls import reverse
from django.utils.http import url_has_allowed_host_and_scheme
from django.utils.translation import gettext_lazy as _
from webauthn.helpers import base64url_to_bytes
from webauthn.helpers.exceptions import (
    InvalidAuthenticationResponse,
    WebAuthnException,
)

from django_security_keys.forms import LoginForm, RegisterKeyForm
from django_security_keys.models import SecurityKey, UserHandle
from django_security_keys.utils import convert_to_bool

logger = logging.getLogger(__name__)


def verify_user_password(
    request: WSGIRequest,
) -> tuple[str | None, JsonResponse | None]:
    """
    Verify the current user's password from POST data.

    Returns:
        tuple: (password, error_response)
            - If valid: (password, None)
            - If missing: (None, JsonResponse with 400)
            - If incorrect: (None, JsonResponse with 401)
    """
    password = request.POST.get("password")
    if not password:
        return None, JsonResponse(
            {"non_field_errors": [_("Password is required.")]},
            status=400,
        )

    if not request.user.check_password(password):
        return None, JsonResponse(
            {"non_field_errors": [_("Incorrect password. Please try again.")]},
            status=401,
        )

    return password, None


def basic_logout(request: WSGIRequest) -> HttpResponseRedirect:
    """
    Very basic logout - mostly provided for bootstrap / testing
    purposes, you should provide your own secure logout view
    """

    logout(request)
    return redirect(reverse("login"))


def basic_login(request: WSGIRequest) -> HttpResponse | HttpResponseRedirect:
    """
    Very basic login handler that supports passkey login
    mostly provided for example / testing purposes, you should
    likely create your own implementation of this
    """

    if request.method == "POST":
        # handle login POST

        form = LoginForm(request.POST)
        if form.is_valid():
            # basic form validation ok
            # has been validated
            password = form.cleaned_data["password"]
            username = form.cleaned_data["username"]
            credential = request.POST.get("credential")
            user = None
            if credential and not (username or password):
                # credential is set and not set username, password, check username in credential.response.userHandle
                try:
                    user_handle = base64url_to_bytes(
                        json.loads(credential)["response"]["userHandle"]
                    ).decode("utf-8")
                    username = UserHandle.objects.get(handle=user_handle).user.username
                    user = authenticate(
                        request, username=username, u2f_credential=credential
                    )
                except (
                    ValueError,
                    KeyError,
                    UserHandle.DoesNotExist,
                    WebAuthnException,
                ) as exc:
                    logger.warning("Passkey login failed: %s", exc, exc_info=True)
                    form.add_error("__all__", "Failed login using passkey")
            else:
                # no credential, attempt to do a normal login with name and password

                user = authenticate(request, username=username, password=password)

            if user is not None:
                # authentication was successful, proceed to login request and
                # redirect accordingly

                login(request, user)
                if request.POST.get("next"):
                    redirect_url = request.POST.get("next")
                    if redirect_url and url_has_allowed_host_and_scheme(
                        redirect_url, allowed_hosts={request.get_host()}
                    ):
                        # false positive from lgtm as url has been passed through
                        # django's validation filter and is safe to redirect

                        return redirect(redirect_url)  # lgtm[py/url-redirection]
                return redirect(settings.LOGIN_REDIRECT_URL)

            else:
                # authentication failure
                if not form.has_error("__all__"):
                    form.add_error("__all__", "Invalid username / password")

        return render(request, "django-security-keys/login.html", {"form": form})
    else:
        form = LoginForm()

    return render(request, "django-security-keys/login.html", {"form": form})


@login_required
def manage_keys(request: WSGIRequest) -> HttpResponse:
    """
    Very basic key management view where user is presented with a list
    of their keys and a form to register new keys.
    """

    context = {"form": RegisterKeyForm()}
    return render(request, "django-security-keys/manage-keys.html", context)


@login_required
def request_registration(request: WSGIRequest, **kwargs: Any) -> JsonResponse:
    """
    Requests webauthn registration options from the server
    as a JSON response.

    Requires password verification before returning registration options.
    POST data:
    - password (`str`): user's current password for verification
    """

    password, error_response = verify_user_password(request)
    if error_response:
        return error_response

    return JsonResponse(
        json.loads(SecurityKey.generate_registration(request.user, request.session))
    )


def request_authentication(request: WSGIRequest, **kwargs: Any) -> JsonResponse:
    """
    Requests webauthn authentications options from the server
    as a JSON response
    """

    username = request.POST.get("username")
    for_login = convert_to_bool(request.POST.get("for_login", False))
    ignore_credential_filter = convert_to_bool(request.POST.get("ignore_credential_filter", False))

    # Security: ignore_credential_filter should ONLY be used for 2FA verification, never for login
    # This prevents bypassing the passkey_login=True requirement during login
    if for_login and ignore_credential_filter:
        return JsonResponse(
            {"non_field_errors": _("Invalid authentication parameters")},
            status=400
        )

    # If user is authenticated and no username provided, use authenticated username
    if not username and request.user.is_authenticated:
        username = request.user.username

    if not for_login and not username:
        return JsonResponse({"non_field_errors": _("No username supplied")}, status=400)
    return JsonResponse(
        json.loads(
            SecurityKey.generate_authentication(
                username, request.session, for_login=for_login,
                ignore_credential_filter=ignore_credential_filter
            )
        )
    )


@login_required
@transaction.atomic
def register_security_key(request: WSGIRequest, **kwargs: Any) -> JsonResponse:
    """
    Register a webauthn security key.

    This requires the following POST data:

    - credential(`base64`): registration credential
    - name(`str`): key nick name
    - passkey_login (`bool`): allow passkey login
    - password (`str`): user's current password for verification

    Returns a JSON response
    """

    password, error_response = verify_user_password(request)
    if error_response:
        return error_response

    name = request.POST.get("name", "security-key")
    credential = request.POST.get("credential")
    passkey_login = convert_to_bool(request.POST.get("passkey_login", False))

    security_key = SecurityKey.verify_registration(
        request.user,
        request.session,
        credential,
        name=name,
        passkey_login=passkey_login,
    )

    return JsonResponse(
        {"status": "ok", "name": security_key.name, "id": security_key.id}
    )


@login_required
@transaction.atomic
def register_security_key_form(request: WSGIRequest, **kwargs: Any) -> HttpResponse:
    """
    Register a webauthn security key with a static form approach.

    This requires the following POST data:

    - credential(`base64`): registration credential
    - name(`str`): key nick name
    - passkey_login (`string`): "on" if enabled
    - password (`str`): user's current password for verification

    This will return a html response
    """

    form = RegisterKeyForm(request.POST, user=request.user)

    if form.is_valid():
        SecurityKey.verify_registration(
            request.user,
            request.session,
            form.cleaned_data["credential"],
            name=form.cleaned_data["name"] or "security-key",
            passkey_login=form.cleaned_data["passkey_login"],
        )
        return redirect(reverse("security-keys:manage-keys"))
    else:
        context = {"form": form}
        return render(request, "django-security-keys/manage-keys.html", context)


@transaction.atomic
def verify_authentication(request: WSGIRequest) -> JsonResponse:
    """
    Verify the authentication attempt.

    This requires the following POST data:

    - credential(`base64`): registration credential
    - username(`str`): username
    - auth_type(`str`): "login" or "mfa"

    ### Authentication typers

    #### login

    the attempt is for a passkey login process and will only
    success if the chosen key has that option enabled.

    #### 2fa

    the attempt is for 2fa process

    """

    credential = request.POST.get("credential")
    username = request.POST.get("username")

    try:
        SecurityKey.verify_authentication(
            username,
            request.session,
            credential,
            for_login=(request.POST.get("auth_type") == "login"),
        )
    except (InvalidAuthenticationResponse, WebAuthnException, ValueError) as exc:
        logger.warning(
            "Security key authentication failed for user %s: %s",
            username,
            exc,
            exc_info=True,
        )
        return JsonResponse(
            {"non_field_errors": "Security authentication failed"}, status=401
        )

    return JsonResponse(
        {
            "status": "ok",
        }
    )


@login_required
def remove_security_key(request: WSGIRequest, **kwargs: Any) -> JsonResponse:
    """
    Decommission a security key.

    This requires the following POST data:

    - id (`int`): key id
    - credential (`str`, optional): security key credential for verification
    - otp_token (`str`, optional): TOTP token for verification

    The key needs to belong the requesting user.
    Either credential or otp_token must be provided for verification.

    Returns a JSON response
    """

    id = request.POST.get("id")
    credential = request.POST.get("credential")
    otp_token = request.POST.get("otp_token")

    try:
        sec_key = request.user.webauthn_security_keys.get(pk=id)
    except SecurityKey.DoesNotExist:
        return JsonResponse({"non_field_errors": [_("Key not found")]}, status=404)

    # Verify 2FA before allowing deletion
    verified = False

    # Try TOTP verification first if token is provided
    if otp_token:
        device = match_token(request.user, otp_token)
        if device:
            verified = True

    # Try security key verification if credential is provided
    if not verified and credential:
        try:
            SecurityKey.verify_authentication(
                request.user.username, request.session, credential
            )
            verified = True
        except (InvalidAuthenticationResponse, WebAuthnException, ValueError) as exc:
            logger.warning(
                "Security key verification failed for user %s during key removal: %s",
                request.user.username,
                exc,
                exc_info=True,
            )

    if not verified:
        return JsonResponse(
            {"non_field_errors": [_("2FA verification required to remove security key")]},
            status=403,
        )

    sec_key.delete()

    return JsonResponse(
        {
            "status": "ok",
        }
    )


@login_required
def remove_security_key_form(
    request: WSGIRequest, **kwargs: Any
) -> HttpResponseRedirect | JsonResponse:
    """
    Decommision a security key through a static form approach.

    This requires the following POST data:

    - id (`int`): key id
    - credential (`str`, optional): security key credential for verification
    - otp_token (`str`, optional): TOTP token for verification

    The key needs to belong to the requesting user.
    Either credential or otp_token must be provided for verification.

    Returns a redirect response to manage-keys on success,
    or the error response if 2FA verification fails.
    """

    response = remove_security_key(request, **kwargs)

    # If removal failed (non-200 status), return the error response
    if response.status_code != 200:
        return response

    return redirect(reverse("security-keys:manage-keys"))


@login_required
@transaction.atomic
def update_security_key(request: WSGIRequest, **kwargs: Any) -> JsonResponse:
    """
    Update a security key's passkey login status.

    This requires the following POST data:
    - id (`int`): key id
    - passkey_login (`bool`): whether to enable passkey login

    Returns a JSON response with the updated key's details
    """
    id = request.POST.get("id")
    passkey_login = convert_to_bool(request.POST.get("passkey_login", False))

    try:
        sec_key = request.user.webauthn_security_keys.get(pk=id)
    except SecurityKey.DoesNotExist:
        return JsonResponse({"non_field_errors": [_("Key not found")]}, status=404)

    sec_key.passkey_login = passkey_login
    sec_key.save()

    return JsonResponse(
        {
            "status": "ok",
            "id": sec_key.id,
            "name": sec_key.name,
            "passkey_login": sec_key.passkey_login,
        }
    )
