import json
from unittest.mock import MagicMock, PropertyMock, patch

import pytest
from django.test import Client, RequestFactory
from django.urls import reverse
from django_otp.plugins.otp_static.models import StaticDevice, StaticToken
from django_otp.plugins.otp_totp.models import TOTPDevice

from django_security_keys.ext.two_factor.forms import (
    PasswordConfirmationForm,
    SecurityKeyDeviceValidation,
)
from django_security_keys.ext.two_factor.views import LoginView
from django_security_keys.models import SecurityKey


@pytest.mark.django_db
def test_login(user):
    c = Client()
    response = c.get(reverse("login"))
    assert response.status_code == 200

    response = c.post(reverse("login"), {"username": user.username, "password": "user"})
    assert response.status_code == 302

    response = c.get(reverse("security-keys:manage-keys"))
    assert "Your keys" in response.content.decode("utf-8")


@pytest.mark.django_db
def test_passkey_login(test_auth_credential_passkey):
    user, session, cred = test_auth_credential_passkey

    key = user.webauthn_security_keys.first()
    key.passkey_login = True
    key.save()

    c = Client()
    response = c.get(reverse("login"))
    assert response.status_code == 200

    client_session = c.session
    SecurityKey.set_challenge(client_session, SecurityKey.get_challenge(session))
    client_session.save()
    response = c.post(reverse("login"), {"credential": cred})
    assert response.status_code == 302

    response = c.get(reverse("security-keys:manage-keys"))
    assert "Your keys" in response.content.decode("utf-8")


@pytest.mark.django_db
def test_passkey_login_failure_invalid_signature(invalid_auth_credential):
    user, session, cred = invalid_auth_credential

    key = user.webauthn_security_keys.first()
    key.passkey_login = True
    key.save()

    c = Client()
    response = c.get(reverse("login"))
    assert response.status_code == 200

    client_session = c.session
    SecurityKey.set_challenge(client_session, SecurityKey.get_challenge(session))
    client_session.save()

    response = c.post(reverse("login"), {"credential": cred})

    response = c.get(reverse("security-keys:manage-keys"))
    assert "Your keys" not in response.content.decode("utf-8")


@pytest.mark.django_db
def test_passkey_login_failure_key_not_enabled(test_auth_credential):
    user, session, cred = test_auth_credential

    c = Client()
    response = c.get(reverse("login"))
    assert response.status_code == 200

    client_session = c.session
    SecurityKey.set_challenge(client_session, SecurityKey.get_challenge(session))
    client_session.save()

    response = c.post(reverse("login"), {"credential": cred})

    response = c.get(reverse("security-keys:manage-keys"))
    assert "Your keys" not in response.content.decode("utf-8")


@pytest.mark.django_db
def test_django_two_factor_auth(test_auth_credential):
    c = Client()

    response = c.get(reverse("two-factor-auth:login"))
    assert response.status_code == 200

    c = Client()

    user, session, cred = test_auth_credential

    response = c.post(
        reverse("two-factor-auth:login"),
        {
            "auth-username": user.username,
            "auth-password": "user",
            "login_view-current_step": "auth",
        },
    )
    assert 'data-2fa-method="security-key"' in response.content.decode("utf-8")


@pytest.mark.django_db
def test_django_two_factor_auth_passkey_login(test_auth_credential_passkey):
    user, session, cred = test_auth_credential_passkey

    key = user.webauthn_security_keys.first()
    key.passkey_login = True
    key.save()

    c = Client()

    client_session = c.session
    SecurityKey.set_challenge(client_session, SecurityKey.get_challenge(session))
    client_session.save()

    response = c.post(
        reverse("two-factor-auth:login"),
        {"credential": cred},
    )
    print(response.content)
    assert response.status_code == 302


@pytest.mark.django_db
def test_manage_keys(security_key):
    user, session, key = security_key

    c = Client()
    c.force_login(user)

    response = c.get(reverse("security-keys:manage-keys"))

    content = response.content.decode("utf-8")

    assert "Your keys" in content
    assert "security-key" in content
    assert "Decommission" in content


@pytest.mark.django_db
def test_request_registration(user):
    c = Client()
    c.force_login(user)

    response = c.post(
        reverse("security-keys:request-registration"), {"password": "user"}
    )

    content = json.loads(response.content.decode("utf-8"))

    assert content
    assert content["rp"]["name"] == "dsk sandbox"


@pytest.mark.django_db
def test_request_registration_no_password(user):
    """Test that request_registration fails without password."""
    c = Client()
    c.force_login(user)

    response = c.post(reverse("security-keys:request-registration"))

    assert response.status_code == 400
    content = json.loads(response.content.decode("utf-8"))
    assert "non_field_errors" in content


@pytest.mark.django_db
def test_request_registration_wrong_password(user):
    """Test that request_registration fails with wrong password."""
    c = Client()
    c.force_login(user)

    response = c.post(
        reverse("security-keys:request-registration"), {"password": "wrong_password"}
    )

    assert response.status_code == 401
    content = json.loads(response.content.decode("utf-8"))
    assert "non_field_errors" in content


@pytest.mark.django_db
def test_request_authentication(user):
    c = Client()
    c.force_login(user)

    response = c.post(
        reverse("security-keys:request-authentication"), {"username": user.username}
    )

    content = json.loads(response.content.decode("utf-8"))

    assert content
    assert content["challenge"]


@pytest.mark.django_db
def test_register_security_key(test_credential):
    user, session, cred = test_credential

    c = Client()
    c.force_login(user)

    client_session = c.session
    SecurityKey.set_challenge(client_session, SecurityKey.get_challenge(session))
    client_session.save()

    response = c.post(
        reverse("security-keys:register"),
        {
            "name": "test-key",
            "credential": cred,
            "password": "user",
        },
    )

    content = json.loads(response.content.decode("utf-8"))

    assert content
    assert content["status"] == "ok"

    assert user.webauthn_security_keys.count() == 1
    assert user.webauthn_security_keys.first().name == "test-key"


@pytest.mark.django_db
def test_register_security_key_no_password(test_credential):
    """Test that register_security_key fails without password."""
    user, session, cred = test_credential

    c = Client()
    c.force_login(user)

    client_session = c.session
    SecurityKey.set_challenge(client_session, SecurityKey.get_challenge(session))
    client_session.save()

    response = c.post(
        reverse("security-keys:register"),
        {
            "name": "test-key",
            "credential": cred,
        },
    )

    assert response.status_code == 400
    content = json.loads(response.content.decode("utf-8"))
    assert "non_field_errors" in content


@pytest.mark.django_db
def test_register_security_key_wrong_password(test_credential):
    """Test that register_security_key fails with wrong password."""
    user, session, cred = test_credential

    c = Client()
    c.force_login(user)

    client_session = c.session
    SecurityKey.set_challenge(client_session, SecurityKey.get_challenge(session))
    client_session.save()

    response = c.post(
        reverse("security-keys:register"),
        {
            "name": "test-key",
            "credential": cred,
            "password": "wrong_password",
        },
    )

    assert response.status_code == 401
    content = json.loads(response.content.decode("utf-8"))
    assert "non_field_errors" in content


@pytest.mark.django_db
def test_register_security_key_form(test_credential):
    user, session, cred = test_credential

    c = Client()
    c.force_login(user)

    client_session = c.session
    SecurityKey.set_challenge(client_session, SecurityKey.get_challenge(session))
    client_session.save()

    response = c.post(
        reverse("security-keys:register-form"),
        {
            "name": "test-key",
            "credential": cred,
            "password": "user",
        },
    )

    assert response.status_code == 302

    assert user.webauthn_security_keys.count() == 1
    assert user.webauthn_security_keys.first().name == "test-key"


@pytest.mark.django_db
def test_verify_authentication(test_auth_credential):
    user, session, cred = test_auth_credential

    c = Client()

    client_session = c.session
    SecurityKey.set_challenge(client_session, SecurityKey.get_challenge(session))
    client_session.save()

    response = c.post(
        reverse("security-keys:authenticate"),
        {
            "username": user.username,
            "credential": cred,
            "auth_type": "2fa",
        },
    )

    print(response.content)

    content = json.loads(response.content.decode("utf-8"))

    assert content
    assert content["status"] == "ok"


@pytest.mark.django_db
def test_remove_security_key_requires_2fa(security_key):
    """Test that removing a security key without 2FA verification fails."""
    user, session, key = security_key

    c = Client()
    c.force_login(user)

    # Attempt to remove without 2FA verification - should fail
    response = c.post(reverse("security-keys:decommission"), {"id": key.id})

    assert response.status_code == 403

    # Key should still exist
    assert user.webauthn_security_keys.count() == 1

    content = json.loads(response.content.decode("utf-8"))
    assert "2FA verification required" in content["non_field_errors"][0]


@pytest.mark.django_db
def test_remove_security_key_with_credential(test_auth_credential):
    """Test that removing a security key with valid credential succeeds."""
    user, session, cred = test_auth_credential
    key = user.webauthn_security_keys.first()

    c = Client()
    c.force_login(user)

    # Set the challenge in client session
    client_session = c.session
    SecurityKey.set_challenge(client_session, SecurityKey.get_challenge(session))
    client_session.save()

    # Remove with valid credential
    response = c.post(
        reverse("security-keys:decommission"), {"id": key.id, "credential": cred}
    )

    assert response.status_code == 200

    assert user.webauthn_security_keys.count() == 0

    content = json.loads(response.content.decode("utf-8"))
    assert content["status"] == "ok"


@pytest.mark.django_db
def test_remove_security_key_with_invalid_credential(test_auth_credential):
    """Test that removing a security key with invalid credential fails."""
    user, session, cred = test_auth_credential
    key = user.webauthn_security_keys.first()

    # Create an invalid credential by modifying the signature
    invalid_cred = json.loads(cred)
    invalid_cred["response"]["signature"] = invalid_cred["response"][
        "signature"
    ].replace("o", "A")
    invalid_cred = json.dumps(invalid_cred)

    c = Client()
    c.force_login(user)

    # Set the challenge in client session
    client_session = c.session
    SecurityKey.set_challenge(client_session, SecurityKey.get_challenge(session))
    client_session.save()

    # Remove with invalid credential - should fail
    response = c.post(
        reverse("security-keys:decommission"),
        {"id": key.id, "credential": invalid_cred},
    )

    assert response.status_code == 403

    # Key should still exist
    assert user.webauthn_security_keys.count() == 1


@pytest.mark.django_db
def test_remove_security_key_form_requires_2fa(security_key):
    """Test that removing a security key via form without 2FA verification fails."""
    user, session, key = security_key

    c = Client()
    c.force_login(user)

    response = c.post(reverse("security-keys:decommission-form"), {"id": key.id})

    # Should fail with 403 since no 2FA provided
    assert response.status_code == 403
    assert user.webauthn_security_keys.count() == 1


@pytest.mark.django_db
def test_password_confirmation_form_valid(user):
    """Test that PasswordConfirmationForm accepts correct password."""

    # Create a mock request object
    class MockRequest:
        pass

    request = MockRequest()

    form = PasswordConfirmationForm(
        request=request, user=user, data={"password": "user"}
    )
    assert form.is_valid(), form.errors


@pytest.mark.django_db
def test_password_confirmation_form_invalid(user):
    """Test that PasswordConfirmationForm rejects incorrect password."""

    # Create a mock request object
    class MockRequest:
        pass

    request = MockRequest()

    form = PasswordConfirmationForm(
        request=request, user=user, data={"password": "wrong_password"}
    )
    assert not form.is_valid()
    assert "password" in form.errors


@pytest.mark.django_db
def test_password_confirmation_form_empty(user):
    """Test that PasswordConfirmationForm rejects empty password."""

    # Create a mock request object
    class MockRequest:
        pass

    request = MockRequest()

    form = PasswordConfirmationForm(request=request, user=user, data={"password": ""})
    assert not form.is_valid()
    assert "password" in form.errors


@pytest.mark.django_db
def test_request_authentication_ignore_credential_filter(security_key_passkey):
    """Test that ignore_credential_filter returns all keys regardless of passkey_login setting."""
    user, session, key = security_key_passkey

    c = Client()
    c.force_login(user)

    # Without ignore_credential_filter, for_login=False should return 0 keys
    # (since the key has passkey_login=True)
    response = c.post(
        reverse("security-keys:request-authentication"), {"username": user.username}
    )
    content = json.loads(response.content.decode("utf-8"))
    assert len(content["allowCredentials"]) == 0

    # With ignore_credential_filter=1, should return all keys
    response = c.post(
        reverse("security-keys:request-authentication"),
        {"username": user.username, "ignore_credential_filter": "1"},
    )
    content = json.loads(response.content.decode("utf-8"))
    assert len(content["allowCredentials"]) == 1


@pytest.mark.django_db
def test_request_authentication_ignore_credential_filter_blocked_for_login(
    security_key_passkey,
):
    """Test that ignore_credential_filter cannot be used with for_login=True."""
    user, session, key = security_key_passkey

    c = Client()
    c.force_login(user)

    # Attempting to use ignore_credential_filter with for_login should fail
    response = c.post(
        reverse("security-keys:request-authentication"),
        {"username": user.username, "for_login": "1", "ignore_credential_filter": "1"},
    )

    assert response.status_code == 400
    content = json.loads(response.content.decode("utf-8"))
    assert "Invalid authentication parameters" in content["non_field_errors"]


@pytest.mark.django_db
def test_request_authentication_uses_authenticated_user(security_key):
    """Test that request_authentication uses authenticated user's username when not provided."""
    user, session, key = security_key

    c = Client()
    c.force_login(user)

    # Request without username - should use authenticated user
    response = c.post(
        reverse("security-keys:request-authentication"),
        {"ignore_credential_filter": "1"},
    )

    assert response.status_code == 200
    content = json.loads(response.content.decode("utf-8"))
    # Should return credentials for the authenticated user
    assert len(content["allowCredentials"]) == 1


# --- Tests for login wizard step conditions ---


def _make_mock_login_view(user, storage_data=None, step_data=None):
    """
    Create a mock LoginView instance with controlled storage
    for directly testing condition methods.
    """
    view = LoginView.__new__(LoginView)

    # Mock storage
    view.storage = MagicMock()
    view.storage.data = storage_data or {}

    def get_step_data(step):
        if step_data and step in step_data:
            return step_data[step]
        return None

    view.storage.get_step_data = get_step_data
    view.storage.validated_step_data = {}

    # Mock get_user to return our user
    view.get_user = lambda: user

    # Mock remember_agent (from django-two-factor)
    type(view).remember_agent = PropertyMock(return_value=False)

    return view


@pytest.mark.django_db
def test_has_security_key_step_false_after_backup(security_key):
    """
    Test that has_security_key_step returns False when backup step data exists.
    Regression test for GitHub issue #1912: backup codes should skip U2F.
    """
    user, session, key = security_key
    view = _make_mock_login_view(
        user,
        step_data={"backup": {"backup-otp_token": "used_token"}},
    )

    assert view.has_security_key_step() is False


@pytest.mark.django_db
def test_has_security_key_step_false_after_passkey(security_key):
    """
    Test that has_security_key_step returns False when passkey_authenticated
    flag is set.
    """
    user, session, key = security_key
    view = _make_mock_login_view(
        user,
        storage_data={"passkey_authenticated": True},
    )

    assert view.has_security_key_step() is False


@pytest.mark.django_db
def test_has_token_step_false_after_passkey(security_key):
    """
    Test that has_token_step returns False when passkey_authenticated flag is set.
    """
    user, session, key = security_key

    # User needs a TOTP device for has_token_step to normally return True
    TOTPDevice.objects.create(user=user, confirmed=True)

    view = _make_mock_login_view(
        user,
        storage_data={"passkey_authenticated": True},
    )

    assert view.has_token_step() is False


@pytest.mark.django_db
def test_has_backup_step_false_after_passkey(security_key):
    """
    Test that has_backup_step returns False when passkey_authenticated flag is set.
    """
    user, session, key = security_key

    # User needs devices for has_backup_step to normally return True
    TOTPDevice.objects.create(user=user, confirmed=True)
    static_device = StaticDevice.objects.create(user=user, confirmed=True)
    StaticToken.objects.create(device=static_device, token="backup123")

    view = _make_mock_login_view(
        user,
        storage_data={"passkey_authenticated": True},
    )

    assert view.has_backup_step() is False


# --- Tests for passkey policy flag properties ---


def _make_login_view_with_flags(user, storage_data=None, **flags):
    """
    Like _make_mock_login_view but creates a one-off subclass with the given
    flag properties so policy enforcement can be tested without a real org model.
    Using a fresh subclass (not setattr on LoginView) avoids class-level mutation
    that would leak flag values across tests.
    """
    overrides = {name: property(lambda self, v=value: v) for name, value in flags.items()}
    SubView = type("_TestLoginView", (LoginView,), overrides)

    view = SubView.__new__(SubView)
    view.storage = MagicMock()
    view.storage.data = storage_data or {}
    view.storage.get_step_data = lambda step: None
    view.storage.validated_step_data = {}
    view.get_user = lambda: user
    type(view).remember_agent = PropertyMock(return_value=False)
    return view


@pytest.mark.django_db
def test_has_token_step_disable_totp_non_passkey(security_key):
    """
    has_token_step returns False when disable_totp is set and the user is on
    the non-passkey login path.
    """
    user, session, key = security_key
    TOTPDevice.objects.create(user=user, confirmed=True)

    view = _make_login_view_with_flags(user, storage_data={}, disable_totp=True)

    assert view.has_token_step() is False


@pytest.mark.django_db
def test_has_token_step_require_passkey_mfa_after_passkey(security_key):
    """
    has_token_step returns True when require_passkey_mfa is set and the user
    authenticated via passkey.
    """
    user, session, key = security_key
    TOTPDevice.objects.create(user=user, name="default", confirmed=True)

    view = _make_login_view_with_flags(
        user,
        storage_data={"passkey_authenticated": True},
        require_passkey_mfa=True,
    )

    assert view.has_token_step() is True


@pytest.mark.django_db
def test_has_token_step_passkey_no_mfa_required(security_key):
    """
    has_token_step returns False after passkey auth when require_passkey_mfa is not set.
    """
    user, session, key = security_key
    TOTPDevice.objects.create(user=user, confirmed=True)

    view = _make_login_view_with_flags(
        user, storage_data={"passkey_authenticated": True}
    )

    assert view.has_token_step() is False


@pytest.mark.django_db
def test_has_backup_step_disable_totp_non_passkey(security_key):
    """
    has_backup_step returns False when disable_totp is set and the user is on
    the non-passkey path (backup codes are tied to TOTP).
    """
    user, session, key = security_key
    TOTPDevice.objects.create(user=user, confirmed=True)
    static_device = StaticDevice.objects.create(user=user, confirmed=True)
    StaticToken.objects.create(device=static_device, token="backup123")

    view = _make_login_view_with_flags(user, storage_data={}, disable_totp=True)

    assert view.has_backup_step() is False


@pytest.mark.django_db
def test_has_backup_step_require_passkey_mfa_after_passkey(security_key):
    """
    has_backup_step returns True when require_passkey_mfa is set and the user
    authenticated via passkey.
    """
    user, session, key = security_key
    TOTPDevice.objects.create(user=user, name="default", confirmed=True)
    static_device = StaticDevice.objects.create(user=user, confirmed=True)
    StaticToken.objects.create(device=static_device, token="backup123")

    view = _make_login_view_with_flags(
        user,
        storage_data={"passkey_authenticated": True},
        require_passkey_mfa=True,
    )

    assert view.has_backup_step() is True


@pytest.mark.django_db
def test_has_token_step_disable_totp_overrides_require_passkey_mfa(security_key):
    """
    When disable_totp is set, has_token_step returns False on the passkey path
    even if require_passkey_mfa is also set. A user cannot be asked for a TOTP
    method their org has disallowed.
    """
    user, session, key = security_key
    TOTPDevice.objects.create(user=user, name="default", confirmed=True)

    view = _make_login_view_with_flags(
        user,
        storage_data={"passkey_authenticated": True},
        require_passkey_mfa=True,
        disable_totp=True,
    )

    assert view.has_token_step() is False


@pytest.mark.django_db
def test_has_backup_step_disable_totp_overrides_require_passkey_mfa(security_key):
    """
    When disable_totp is set, has_backup_step returns False on the passkey path
    even if require_passkey_mfa is also set.
    """
    user, session, key = security_key
    TOTPDevice.objects.create(user=user, name="default", confirmed=True)
    static_device = StaticDevice.objects.create(user=user, confirmed=True)
    StaticToken.objects.create(device=static_device, token="backup123")

    view = _make_login_view_with_flags(
        user,
        storage_data={"passkey_authenticated": True},
        require_passkey_mfa=True,
        disable_totp=True,
    )

    assert view.has_backup_step() is False


@pytest.mark.django_db
def test_done_redirects_when_mfa_incomplete_and_hook_returns_url(security_key):
    """
    done() redirects to the URL returned by get_mfa_incomplete_redirect()
    when require_passkey_mfa is True but MFA was not completed.
    """
    user, session, key = security_key

    view = _make_login_view_with_flags(
        user,
        storage_data={"passkey_authenticated": True},
        require_passkey_mfa=True,
    )
    view.get_done_form_list = lambda: {}
    view.get_mfa_incomplete_redirect = lambda: "/mfa/setup/"
    view.storage.reset = MagicMock()

    http_request = RequestFactory().get("/")
    http_request.session = {}
    view.request = http_request

    with patch(
        "django_security_keys.ext.two_factor.views.auth_login"
    ) as mock_auth_login:
        response = view.done([], **{})

    assert response.status_code == 302
    assert response["Location"] == "/mfa/setup/"
    view.storage.reset.assert_called_once()
    mock_auth_login.assert_called_once_with(http_request, user)


@pytest.mark.django_db
def test_done_allows_through_when_mfa_incomplete_and_hook_returns_none(security_key):
    """
    done() proceeds normally when get_mfa_incomplete_redirect() returns None
    (default — backwards compatible).
    """
    user, session, key = security_key

    view = _make_login_view_with_flags(
        user,
        storage_data={"passkey_authenticated": True},
        require_passkey_mfa=True,
    )
    view.get_done_form_list = lambda: {}
    view.get_mfa_incomplete_redirect = lambda: None
    view.storage.reset = MagicMock()

    try:
        view.done([], **{})
    except Exception:
        pass  # super().done() will fail without full wizard state

    view.storage.reset.assert_not_called()


@pytest.mark.django_db
def test_done_skips_redirect_when_security_key_mfa_completed(security_key):
    """
    After tapping a second security key as MFA, the user should be logged in
    normally — not redirected to MFA setup. The "security-key" step completing
    counts as satisfying the MFA requirement.
    """
    user, session, key = security_key

    view = _make_login_view_with_flags(
        user,
        storage_data={"passkey_authenticated": True},
        require_passkey_mfa=True,
    )
    view.get_done_form_list = lambda: {"security-key": None}
    view.get_mfa_incomplete_redirect = MagicMock(return_value="/mfa/setup/")
    view.storage.reset = MagicMock()

    try:
        view.done([], **{})
    except Exception:
        pass  # super().done() will fail without full wizard state

    # MFA was satisfied via security key — must NOT redirect to setup
    view.get_mfa_incomplete_redirect.assert_not_called()
    view.storage.reset.assert_not_called()


@pytest.mark.django_db
def test_done_password_path_calls_mfa_redirect_when_totp_disabled(security_key):
    """
    When TOTP is disabled by policy and a user logged in via password without
    completing a security-key step, done() should call get_mfa_incomplete_redirect()
    to give the app a chance to redirect them to enroll a different MFA method.
    """
    user, session, key = security_key

    view = _make_login_view_with_flags(
        user,
        storage_data={},  # no passkey_authenticated
        disable_totp=True,
    )
    view.get_done_form_list = lambda: {}  # no steps completed
    view.get_mfa_incomplete_redirect = MagicMock(return_value="/mfa/setup/")
    view.storage.reset = MagicMock()

    http_request = RequestFactory().get("/")
    http_request.session = {}
    view.request = http_request

    with patch(
        "django_security_keys.ext.two_factor.views.auth_login"
    ) as mock_auth_login:
        response = view.done([], **{})

    assert response.status_code == 302
    assert response["Location"] == "/mfa/setup/"
    view.get_mfa_incomplete_redirect.assert_called_once()
    view.storage.reset.assert_called_once()
    mock_auth_login.assert_called_once_with(http_request, user)


@pytest.mark.django_db
def test_done_password_path_no_redirect_when_mfa_hook_returns_none(security_key):
    """
    When get_mfa_incomplete_redirect() returns None (user has no TOTP device to
    block), done() should proceed normally without redirecting.
    """
    user, session, key = security_key

    view = _make_login_view_with_flags(
        user,
        storage_data={},
        disable_totp=True,
    )
    view.get_done_form_list = lambda: {}
    view.get_mfa_incomplete_redirect = MagicMock(return_value=None)
    view.storage.reset = MagicMock()

    try:
        view.done([], **{})
    except Exception:
        pass  # super().done() will fail without full wizard state

    view.storage.reset.assert_not_called()


@pytest.mark.django_db
def test_done_password_path_no_redirect_when_security_key_completed(security_key):
    """
    When disable_totp is True but the user satisfied MFA via a security key,
    done() should NOT redirect them — security-key counts as completed MFA.
    """
    user, session, key = security_key

    view = _make_login_view_with_flags(
        user,
        storage_data={},
        disable_totp=True,
    )
    view.get_done_form_list = lambda: {"security-key": None}
    view.get_mfa_incomplete_redirect = MagicMock(return_value="/mfa/setup/")
    view.storage.reset = MagicMock()

    try:
        view.done([], **{})
    except Exception:
        pass  # super().done() will fail without full wizard state

    view.get_mfa_incomplete_redirect.assert_not_called()
    view.storage.reset.assert_not_called()


# --- Tests for passkey + security-key MFA step ---


@pytest.mark.django_db
def test_has_security_key_step_passkey_mfa_required_has_2fa_key(security_key):
    """
    has_security_key_step returns True after passkey auth when require_passkey_mfa
    is set and the user has a 2FA security key (passkey_login=False).
    A second security key can satisfy the MFA requirement.
    """
    user, session, key = security_key
    # key fixture creates passkey_login=False (2FA key) — present in DB.

    view = _make_login_view_with_flags(
        user,
        storage_data={"passkey_authenticated": True},
        require_passkey_mfa=True,
    )

    assert view.has_security_key_step() is True


@pytest.mark.django_db
def test_has_security_key_step_passkey_mfa_required_no_2fa_key(security_key_passkey):
    """
    has_security_key_step returns False after passkey auth when require_passkey_mfa
    is set but the user has no 2FA security key — only the passkey key used to log in.
    credentials(for_login=False) returns nothing, so there is nothing to challenge.
    """
    user, session, key = security_key_passkey
    # security_key_passkey fixture creates passkey_login=True only — no 2FA key.

    view = _make_login_view_with_flags(
        user,
        storage_data={"passkey_authenticated": True},
        require_passkey_mfa=True,
    )

    assert view.has_security_key_step() is False


@pytest.mark.django_db
def test_has_security_key_step_passkey_mfa_required_token_completed(security_key):
    """
    has_security_key_step returns False after passkey auth when require_passkey_mfa
    is set but the token (TOTP) step was already completed.
    TOTP already satisfied the MFA requirement — no need for security key step.
    """
    user, session, key = security_key
    TOTPDevice.objects.create(user=user, name="default", confirmed=True)

    view = _make_login_view_with_flags(
        user,
        storage_data={"passkey_authenticated": True},
        require_passkey_mfa=True,
    )
    view.storage.get_step_data = lambda step: {"token-otp_token": "123456"} if step == "token" else None

    assert view.has_security_key_step() is False


@pytest.mark.django_db
def test_has_security_key_step_passkey_mfa_required_backup_completed(security_key):
    """
    has_security_key_step returns False after passkey auth when require_passkey_mfa
    is set but the backup token step was already completed.
    """
    user, session, key = security_key

    view = _make_login_view_with_flags(
        user,
        storage_data={"passkey_authenticated": True},
        require_passkey_mfa=True,
    )
    view.storage.get_step_data = lambda step: {"backup-otp_token": "abc123"} if step == "backup" else None

    assert view.has_security_key_step() is False


@pytest.mark.django_db
def test_has_security_key_step_passkey_no_mfa_required_still_false(security_key):
    """
    has_security_key_step returns False after passkey auth when require_passkey_mfa
    is not set, even if the user has a 2FA security key.
    Passkey alone satisfies auth — no additional step needed.
    """
    user, session, key = security_key

    view = _make_login_view_with_flags(
        user,
        storage_data={"passkey_authenticated": True},
        require_passkey_mfa=False,
    )

    assert view.has_security_key_step() is False


# --- Tests for POST-tampering defense ---


@pytest.mark.django_db
def test_security_key_form_rejects_passkey_credential(security_key):
    """
    SecurityKeyDeviceValidation.clean() raises ValidationError when the submitted
    credential id matches the passkey_credential_id that was used for login.
    Prevents a user from satisfying the security-key MFA step with the same
    credential they used to authenticate via passkey.
    """
    user, session, key = security_key

    passkey_credential_id = "abc123credentialid"
    credential_json = json.dumps({"id": passkey_credential_id, "response": {}})

    device = MagicMock()
    device.authenticated = False
    device.user = user

    request = RequestFactory().post("/")
    request.session = {}

    form = SecurityKeyDeviceValidation(
        request=request,
        device=device,
        passkey_credential_id=passkey_credential_id,
        data={"credential": credential_json},
    )

    assert not form.is_valid()
    assert any(
        "passkey" in str(e).lower() or "second factor" in str(e).lower()
        for e in form.errors.get("__all__", [])
    )


@pytest.mark.django_db
def test_security_key_form_allows_different_credential(security_key):
    """
    SecurityKeyDeviceValidation.clean() does not raise the tamper error when the
    submitted credential id is different from the passkey_credential_id.
    The form proceeds to verify_authentication normally (which may fail for other
    reasons in a unit test — we only assert the tamper check does not fire).
    """
    user, session, key = security_key

    passkey_credential_id = "abc123credentialid"
    different_credential_json = json.dumps({"id": "different456", "response": {}})

    device = MagicMock()
    device.authenticated = False
    device.user = user

    request = RequestFactory().post("/")
    request.session = {}

    form = SecurityKeyDeviceValidation(
        request=request,
        device=device,
        passkey_credential_id=passkey_credential_id,
        data={"credential": different_credential_json},
    )

    # is_valid() will fail (no real WebAuthn session), but the error should be
    # the WebAuthn verification error, not the tamper check.
    form.is_valid()
    all_errors = " ".join(str(e) for e in form.errors.get("__all__", []))
    assert "second factor" not in all_errors.lower()
    assert "passkey used for login" not in all_errors.lower()
