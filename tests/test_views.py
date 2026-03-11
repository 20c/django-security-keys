import json

import pytest
from django.test import Client
from django.urls import reverse

from django_security_keys.ext.two_factor.forms import PasswordConfirmationForm
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
