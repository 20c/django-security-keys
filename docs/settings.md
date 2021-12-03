## django-security-keys REQUIRED 

These settings should be added to your django project settings.

- `WEBAUTHN_RP_ID`: rp id to use for webauthn, in most cases this would be your hostname (e.g., `localhost` or `www.example.com`)
- `WEBAUTHN_ORIGIN`: http origin to use for webauthn, this should be a url and match the host that originates the registration and authentication requests (e.g., `https://localhost` or `https://www.example.com` or `https://www.example.com:1234`)
- `WEBAUTHN_RP_NAME`: Descriptive name of your service / website.

There are no default values for these as they are crucial for operation.

## django-security-jeys OPTIONAL

- `WEBAUTHN_ATTESTATION` (default=`"none"`): set this to `"direct"` to collect attestation information. Please note that attestation verification is currently not supported in django-security-keys (see [missing features](/docs/missing-features.md)).

## django 

For password-less login to work `django_security_keys.backends.PasswordlessAuthenticationBackend` needs to be added to `AUTHENTICATION_BACKENDS`

It also needs to be added as the first authentication backend.

```
AUTHENTICATION_BACKENDS = (
    # for passwordless auth using security-key
    # this needs to be first so it can do some clean up
    "django_security_keys.backends.PasswordlessAuthenticationBackend",

		# additional auth backends 
    "django.contrib.auth.backends.ModelBackend",
)
```

## Development notes

Currently not many settings for py-webauthn are exposed to the django level and in a lot of cases the default values provided in py-webauthn will be used.

This is being worked on and we plan to improve configuration options in the future.
