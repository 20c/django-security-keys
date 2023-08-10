import json
import secrets

import pytest

from django_security_keys.models import SecurityKey, UserHandle


@pytest.mark.django_db
def test_user_handle_require_for_user(user):
    UserHandle.require_for_user(user)
    assert user.webauthn_user_handle


@pytest.mark.django_db
def test_security_key_challenge(user, session):
    SecurityKey.set_challenge(session, secrets.token_bytes(16))

    assert session.get("webauthn_challenge")
    assert SecurityKey.get_challenge(session)

    SecurityKey.clear_challenge(session)

    with pytest.raises(KeyError):
        SecurityKey.get_challenge(session)


@pytest.mark.django_db
def test_security_key_generate_registration(user, session):
    opts = SecurityKey.generate_registration(user, session)
    assert opts

    opts = json.loads(opts)

    assert opts["rp"]
    assert opts["user"]
    assert opts["challenge"]


@pytest.mark.django_db
def test_security_key_verify_registration(test_credential):
    user, session, credential = test_credential

    key = SecurityKey.verify_registration(user, session, credential)

    assert key
    assert key.id
    assert key.user == user

    with pytest.raises(KeyError):
        SecurityKey.get_challenge(session)


@pytest.mark.django_db
def test_security_key_credentials(security_key):
    user, session, key = security_key

    assert len(SecurityKey.credentials(user.username, session)) == 1
    assert len(SecurityKey.credentials(user.username, session, for_login=True)) == 0


@pytest.mark.django_db
def test_security_key_credentials_passwordless(security_key_passwordless):
    user, session, key = security_key_passwordless

    assert len(SecurityKey.credentials(user.username, session)) == 1
    assert len(SecurityKey.credentials(user.username, session, for_login=True)) == 1


@pytest.mark.django_db
def test_security_key_generate_authentication(user, session):
    opts = SecurityKey.generate_authentication(user, session)

    assert opts

    opts = json.loads(opts)

    assert opts["challenge"]
    assert opts["rpId"] == "localhost"
    assert opts["userVerification"] == "preferred"
    assert opts["timeout"] == 60000


@pytest.mark.django_db
def test_security_key_verify_authentication(test_auth_credential):
    user, session, cred = test_auth_credential

    key = SecurityKey.verify_authentication(user.username, session, cred)
    assert key


@pytest.mark.django_db
def test_security_key_verify_authentication_passwordless_fail(test_auth_credential):
    user, session, cred = test_auth_credential

    with pytest.raises(ValueError):
        SecurityKey.verify_authentication(user.username, session, cred, for_login=True)


@pytest.mark.django_db
def test_security_key_verify_authentication_passwordless_success(test_auth_credential):
    user, session, cred = test_auth_credential

    key = user.webauthn_security_keys.first()
    key.passwordless_login = True
    key.save()

    assert SecurityKey.verify_authentication(
        user.username, session, cred, for_login=True
    )
