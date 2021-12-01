# Installation

```sh
pip install django-security-keys
```

## 2FA requirements

django-security-keys supports two-factor authentication with `django-two-factor`

Install the package if you want to enable 2FA for your site.

```sh
pip install django-two-factor
```

## Settings

### django-security-keys

These settings should be added to your django project settings.

- `WEBAUTHN_RP_ID`: rp id to use for webauthn, in most cases this would be your hostname (e.g., `localhost` or `www.example.com`)
- `WEBAUTHN_ORIGIN`: http origin to use for webauthn, this should be a url and match the host that originates the registration and authentication requests (e.g., `https://localhost` or `https://www.example.com` or `https://www.example.com:1234`)
- `WEBAUTHN_RP_NAME`: Descriptive name of your service / website.

There are no default values for these as they are crucial for operation.

### django 

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

## urls

django-security-keys comes with some very basic views to get you started

Since most django installations will use customized or third-party driven login views, the login view that comes with our package should seen as a very basic but functional implementation example.

For a quick setup add the following lines to your urls.py urlpatterns

```py
import django_security_keys

urlpatterns = [
    path('login/', django_security_keys.views.basic_login, name="login"),
    path('logout/', django_security_keys.views.basic_logout, name="logout"),
    path('security-keys/', include( ('django_security_keys.urls', 'django_security_keys'), namespace="security-keys"))
]
```
