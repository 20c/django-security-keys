import json

import pytest
from django.test import Client
from django.urls import reverse

from django_security_keys.models import SecurityKey

from webauthn.helpers.exceptions import (
    InvalidAuthenticationResponse
)


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
def test_passwordless_login(test_auth_credential):

    user, session, cred = test_auth_credential

    key = user.webauthn_security_keys.first()
    key.passwordless_login = True
    key.save()

    c = Client()
    response = c.get(reverse("login"))
    assert response.status_code == 200

    client_session = c.session
    SecurityKey.set_challenge(client_session, SecurityKey.get_challenge(session))
    client_session.save()

    response = c.post(reverse("login"), {"username": user.username, "credential": cred})
    assert response.status_code == 302

    response = c.get(reverse("security-keys:manage-keys"))
    assert "Your keys" in response.content.decode("utf-8")


@pytest.mark.django_db
def test_passwordless_login_failure_invalid_signature(invalid_auth_credential):

    user, session, cred = invalid_auth_credential

    key = user.webauthn_security_keys.first()
    key.passwordless_login = True
    key.save()

    c = Client()
    response = c.get(reverse("login"))
    assert response.status_code == 200

    client_session = c.session
    SecurityKey.set_challenge(client_session, SecurityKey.get_challenge(session))
    client_session.save()

    with pytest.raises(InvalidAuthenticationResponse):
        response = c.post(reverse("login"), {"username": user.username, "credential": cred})

    response = c.get(reverse("security-keys:manage-keys"))
    assert "Your keys" not in response.content.decode("utf-8")

@pytest.mark.django_db
def test_passwordless_login_failure_key_not_enabled(test_auth_credential):

    user, session, cred = test_auth_credential

    c = Client()
    response = c.get(reverse("login"))
    assert response.status_code == 200

    client_session = c.session
    SecurityKey.set_challenge(client_session, SecurityKey.get_challenge(session))
    client_session.save()

    response = c.post(reverse("login"), {"username": user.username, "credential": cred})

    response = c.get(reverse("security-keys:manage-keys"))
    assert "Your keys" not in response.content.decode("utf-8")


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

    response = c.get(reverse("security-keys:request-registration"))

    content = json.loads(response.content.decode("utf-8"))

    assert content
    assert content["rp"]["name"] == "dsk sandbox"


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
        },
    )

    content = json.loads(response.content.decode("utf-8"))

    assert content
    assert content["status"] == "ok"

    assert user.webauthn_security_keys.count() == 1
    assert user.webauthn_security_keys.first().name == "test-key"


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
def test_remove_security_key(security_key):

    user, session, key = security_key

    c = Client()
    c.force_login(user)

    response = c.post(reverse("security-keys:decommission"), {"id": key.id})

    assert response.status_code == 200

    assert user.webauthn_security_keys.count() == 0

    content = json.loads(response.content.decode("utf-8"))

    assert content
    assert content["status"] == "ok"


@pytest.mark.django_db
def test_remove_security_key_form(security_key):

    user, session, key = security_key

    c = Client()
    c.force_login(user)

    response = c.post(reverse("security-keys:decommission-form"), {"id": key.id})

    assert response.status_code == 302
    assert user.webauthn_security_keys.count() == 0
