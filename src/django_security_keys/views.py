import json

from django.conf import settings
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.db import transaction
from django.http import JsonResponse
from django.shortcuts import redirect, render
from django.urls import reverse
from django.utils.http import url_has_allowed_host_and_scheme
from django.utils.translation import gettext_lazy as _

from django_security_keys.forms import LoginForm, RegisterKeyForm
from django_security_keys.models import SecurityKey


def convert_to_bool(data):
    if data is None:
        return False

    if isinstance(data, bool):
        return data

    if isinstance(data, str):
        return data.lower() == "true"

    return False


def basic_logout(request):

    """
    Very basic logout - mostly provided for bootstrap / testing
    purposes, you should provide your own secure logout view
    """

    logout(request)
    return redirect(reverse("login"))


def basic_login(request):

    """
    Very basic login handler that supports password-less login
    mostly provided for example / testing purposes, you should
    likely create your own implementation of this
    """

    if request.method == "POST":

        # handle login POST

        form = LoginForm(request.POST)
        if form.is_valid():

            # basic form validation ok (at this point only username requirement
            # has been validated

            password = form.cleaned_data["password"]
            username = form.cleaned_data["username"]
            credential = request.POST.get("credential")

            if credential:

                # credential is set, provide it in the authenticate request

                user = authenticate(
                    request, username=username, u2f_credential=credential
                )
            else:

                # no credential, attempt to do a normal login with name and password

                user = authenticate(request, username=username, password=password)

            if user is not None:

                # authentication was successful, proceed to login request and
                # redirect accordingly

                login(request, user)
                if request.POST.get("next"):
                    redirect_url = request.POST.get("next")
                    if url_has_allowed_host_and_scheme(redirect_url):
                        # false positive from lgtm as url has been passed through
                        # django's validation filter and is safe to redirect

                        return redirect(redirect_url)  # lgtm[py/url-redirection]
                return redirect(settings.LOGIN_REDIRECT_URL)

            else:

                # authentication failure

                form.add_error("__all__", "Invalid username / password")

        return render(request, "django-security-keys/login.html", {"form": form})
    else:
        form = LoginForm()

    return render(request, "django-security-keys/login.html", {"form": form})


@login_required
def manage_keys(request):

    """
    Very basic key management view where user is presented with a list
    of their keys and a form to register new keys.
    """

    context = {"form": RegisterKeyForm()}
    return render(request, "django-security-keys/manage-keys.html", context)


@login_required
def request_registration(request, **kwargs):
    """
    Requests webauthn registration options from the server
    as a JSON response
    """

    return JsonResponse(
        json.loads(SecurityKey.generate_registration(request.user, request.session))
    )


def request_authentication(request, **kwargs):
    """
    Requests webauthn authentications options from the server
    as a JSON response

    Expects a `username` POST parameter
    """

    username = request.POST.get("username")
    for_login = request.POST.get("for_login")

    if not username:
        return JsonResponse({"non_field_errors": _("No username supplied")}, status=403)

    return JsonResponse(
        json.loads(
            SecurityKey.generate_authentication(
                username, request.session, for_login=for_login
            )
        )
    )


@login_required
@transaction.atomic
def register_security_key(request, **kwargs):
    """
    Register a webauthn security key.

    This requires the following POST data:

    - credential(`base64`): registration credential
    - name(`str`): key nick name
    - passwordless_login (`bool`): allow passwordless login

    Returns a JSON response
    """

    name = request.POST.get("name", "security-key")
    credential = request.POST.get("credential")
    passwordless_login = convert_to_bool(request.POST.get("passwordless_login", False))

    security_key = SecurityKey.verify_registration(
        request.user,
        request.session,
        credential,
        name=name,
        passwordless_login=passwordless_login,
    )

    return JsonResponse(
        {"status": "ok", "name": security_key.name, "id": security_key.id}
    )


@login_required
@transaction.atomic
def register_security_key_form(request, **kwargs):
    """
    Register a webauthn security key with a static form approach.

    This requires the following POST data:

    - credential(`base64`): registration credential
    - name(`str`): key nick name
    - passwordless_login (`string`): "on" if enabled

    This will return a html response
    """

    form = RegisterKeyForm(request.POST)

    if form.is_valid():
        SecurityKey.verify_registration(
            request.user,
            request.session,
            form.cleaned_data["credential"],
            name=form.cleaned_data["name"] or "security-key",
            passwordless_login=form.cleaned_data["passwordless_login"],
        )
        return redirect(reverse("security-keys:manage-keys"))
    else:
        context = {"form": form}
        return render(request, "django-security-keys/manage-keys.html", context)


@transaction.atomic
def verify_authentication(request):

    """
    Verify the authentication attempt.

    This requires the following POST data:

    - credential(`base64`): registration credential
    - username(`str`): username
    - auth_type(`str`): "login" or "mfa"

    ### Authentication typers

    #### login

    the attempt is for a passwordless login process and will only
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
    except Exception:
        return JsonResponse(
            {"non_field_errors": "Security authentication failed"}, status=403
        )

    return JsonResponse(
        {
            "status": "ok",
        }
    )


@login_required
def remove_security_key(request, **kwargs):
    """
    Decommission a security key.

    This requires the following POST data:

    - id (`int`): key id

    The key needs to belong the requesting user.

    Returns a JSON response
    """

    id = request.POST.get("id")

    try:
        sec_key = request.user.webauthn_security_keys.get(pk=id)
    except SecurityKey.DoesNotExist:
        return JsonResponse({"non_field_errors": [_("Key not found")]}, status=404)
    sec_key.delete()

    return JsonResponse(
        {
            "status": "ok",
        }
    )


@login_required
def remove_security_key_form(request, **kwargs):

    """
    Decommision a security key through a static form approach.

    This requires the following POST data:

    - id (`int`): key id

    The key needs to belong to the requesting user.

    Returns a redirect response to manage-keys
    """

    remove_security_key(request, **kwargs)

    return redirect(reverse("security-keys:manage-keys"))
