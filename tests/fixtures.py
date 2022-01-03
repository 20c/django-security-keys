import json

import pytest
from django.contrib.auth import get_user_model
from django.contrib.sessions.backends.db import SessionStore
from webauthn.helpers import base64url_to_bytes

__all__ = [
    "session",
    "user",
    "test_credential",
    "test_auth_credential",
    "invalid_auth_credential",
    "invalid_test_credential",
    "security_key",
    "security_key_passwordless",
]


@pytest.fixture
def user():
    return get_user_model().objects.create_user("bob", password="user")


@pytest.fixture
def session():
    session = SessionStore()
    session.create()
    return session


@pytest.fixture
def test_credential():
    return _test_credential()


@pytest.fixture
def invalid_test_credential():
    user, session, cred = _test_credential

    cred = json.loads(cred)
    cred["response"]["attestationObject"] = cred["response"][
        "attestationObject"
    ].replace("o", "A")
    cred = json.dumps(cred)

    return (user, session, cred)


@pytest.fixture
def test_auth_credential():
    return _test_auth_credential()


@pytest.fixture
def invalid_auth_credential():
    user, session, cred = _test_auth_credential()

    cred = json.loads(cred)
    cred["response"]["signature"] = cred["response"]["signature"].replace("o", "A")
    cred = json.dumps(cred)

    return (user, session, cred)


@pytest.fixture
def security_key():
    return _security_key()


@pytest.fixture
def security_key_passwordless():
    return _security_key(passwordless_login=True)


def _test_credential():

    from django_security_keys.models import SecurityKey, UserHandle

    user = get_user_model().objects.create_user("bob", password="user")
    session = SessionStore()
    session.create()

    # update user handle to fit the test-credential below
    UserHandle.require_for_user(user)
    user.webauthn_user_handle.handle = "12345"
    user.webauthn_user_handle.save()

    # update challenge to fit the test-credential below
    SecurityKey.set_challenge(
        session,
        base64url_to_bytes(
            "CeTWogmg0cchuiYuFrv8DXXdMZSIQRVZJOga_xayVVEcBj0Cw3y73yhD4FkGSe-RrP6hPJJAIm3LVien4hXELg"
        ),
    )

    # test-credential taken from py-webauthn registration example
    cred = json.dumps(
        {
            "id": "ZoIKP1JQvKdrYj1bTUPJ2eTUsbLeFkv-X5xJQNr4k6s",
            "rawId": "ZoIKP1JQvKdrYj1bTUPJ2eTUsbLeFkv-X5xJQNr4k6s",
            "response": {
                "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVkBZ0mWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjRQAAAAAAAAAAAAAAAAAAAAAAAAAAACBmggo_UlC8p2tiPVtNQ8nZ5NSxst4WS_5fnElA2viTq6QBAwM5AQAgWQEA31dtHqc70D_h7XHQ6V_nBs3Tscu91kBL7FOw56_VFiaKYRH6Z4KLr4J0S12hFJ_3fBxpKfxyMfK66ZMeAVbOl_wemY4S5Xs4yHSWy21Xm_dgWhLJjZ9R1tjfV49kDPHB_ssdvP7wo3_NmoUPYMgK-edgZ_ehttp_I6hUUCnVaTvn_m76b2j9yEPReSwl-wlGsabYG6INUhTuhSOqG-UpVVQdNJVV7GmIPHCA2cQpJBDZBohT4MBGme_feUgm4sgqVCWzKk6CzIKIz5AIVnspLbu05SulAVnSTB3NxTwCLNJR_9v9oSkvphiNbmQBVQH1tV_psyi9HM1Jtj9VJVKMeyFDAQAB",
                "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiQ2VUV29nbWcwY2NodWlZdUZydjhEWFhkTVpTSVFSVlpKT2dhX3hheVZWRWNCajBDdzN5NzN5aEQ0RmtHU2UtUnJQNmhQSkpBSW0zTFZpZW40aFhFTGciLCJvcmlnaW4iOiJodHRwOi8vbG9jYWxob3N0OjUwMDAiLCJjcm9zc09yaWdpbiI6ZmFsc2V9",
            },
            "type": "public-key",
            "clientExtensionResults": {},
            "transports": ["internal"],
        }
    )

    return (user, session, cred)


def _test_auth_credential():

    from django_security_keys.models import SecurityKey

    user, session, key = _security_key()

    # update challenge to fit the test-credential below
    SecurityKey.set_challenge(
        session,
        base64url_to_bytes(
            "iPmAi1Pp1XL6oAgq3PWZtZPnZa1zFUDoGbaQ0_KvVG1lF2s3Rt_3o4uSzccy0tmcTIpTTT4BU1T-I4maavndjQ"
        ),
    )

    # print(key.credential_id)
    # print(key.credential_public_key)
    # print("-"*80)

    # key.credential_id = "ZoIKP1JQvKdrYj1bTUPJ2eTUsbLeFkv-X5xJQNr4k6s"
    # key.credential_public_key = "pAEDAzkBACBZAQDfV20epzvQP-HtcdDpX-cGzdOxy73WQEvsU7Dnr9UWJophEfpngouvgnRLXaEUn_d8HGkp_HIx8rrpkx4BVs6X_B6ZjhLlezjIdJbLbVeb92BaEsmNn1HW2N9Xj2QM8cH-yx28_vCjf82ahQ9gyAr552Bn96G22n8jqFRQKdVpO-f-bvpvaP3IQ9F5LCX7CUaxptgbog1SFO6FI6ob5SlVVB00lVXsaYg8cIDZxCkkENkGiFPgwEaZ7995SCbiyCpUJbMqToLMgojPkAhWeyktu7TlK6UBWdJMHc3FPAIs0lH_2_2hKS-mGI1uZAFVAfW1X-mzKL0czUm2P1UlUox7IUMBAAE"
    # key.save()

    # test-credential taken from py-webauthn registration example
    cred = json.dumps(
        {
            "id": "ZoIKP1JQvKdrYj1bTUPJ2eTUsbLeFkv-X5xJQNr4k6s",
            "rawId": "ZoIKP1JQvKdrYj1bTUPJ2eTUsbLeFkv-X5xJQNr4k6s",
            "response": {
                "authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFAAAAAQ",
                "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiaVBtQWkxUHAxWEw2b0FncTNQV1p0WlBuWmExekZVRG9HYmFRMF9LdlZHMWxGMnMzUnRfM280dVN6Y2N5MHRtY1RJcFRUVDRCVTFULUk0bWFhdm5kalEiLCJvcmlnaW4iOiJodHRwOi8vbG9jYWxob3N0OjUwMDAiLCJjcm9zc09yaWdpbiI6ZmFsc2V9",
                "signature": "iOHKX3erU5_OYP_r_9HLZ-CexCE4bQRrxM8WmuoKTDdhAnZSeTP0sjECjvjfeS8MJzN1ArmvV0H0C3yy_FdRFfcpUPZzdZ7bBcmPh1XPdxRwY747OrIzcTLTFQUPdn1U-izCZtP_78VGw9pCpdMsv4CUzZdJbEcRtQuRS03qUjqDaovoJhOqEBmxJn9Wu8tBi_Qx7A33RbYjlfyLm_EDqimzDZhyietyop6XUcpKarKqVH0M6mMrM5zTjp8xf3W7odFCadXEJg-ERZqFM0-9Uup6kJNLbr6C5J4NDYmSm3HCSA6lp2iEiMPKU8Ii7QZ61kybXLxsX4w4Dm3fOLjmDw",
                "userHandle": "T1RWa1l6VXdPRFV0WW1NNVlTMDBOVEkxTFRnd056Z3RabVZpWVdZNFpEVm1ZMk5p",
            },
            "type": "public-key",
            "clientExtensionResults": {},
        }
    )

    return (user, session, cred)


def _security_key(passwordless_login=False):

    from django_security_keys.models import SecurityKey

    user, session, cred = _test_credential()

    key = SecurityKey.verify_registration(
        user, session, cred, passwordless_login=passwordless_login
    )

    return (user, session, key)
