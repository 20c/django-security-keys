# Installation

```sh
pip install django-security-keys
```

## 2FA requirements

django-security-keys supports two-factor authentication with `django-two-factor`.

Install the package if you want to enable 2FA for your site.

```sh
pip install django-two-factor-auth
```

## Settings

### django-security-keys

These settings should be added to your Django project settings.

- `WEBAUTHN_RP_ID`: rp id to use for webauthn, in most cases this would be your hostname (e.g., `localhost` or `www.example.com`)
- `WEBAUTHN_ORIGIN`: http origin to use for webauthn, this should be a URL and match the host that originates the registration and authentication requests (e.g., `https://localhost` or `https://www.example.com` or `https://www.example.com:1234`)
- `WEBAUTHN_RP_NAME`: Descriptive name of your service / website.

There are no default values for these as they are crucial for operation.

### Django 

Add `django_security_keys` and `django_otp` to your `INSTALLED_APPS`

```py
INSTALLED_APPS += [
  "django_security_keys",
  "django_otp",
]
```

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

Since most Django installations will use customized or third-party driven login views, the login view that comes with our package should be seen as a very basic but functional implementation example.

For a quick setup add the following lines to your `urls.py` `urlpatterns`.

```py
from django.urls import path, include
import django_security_keys

urlpatterns = [
    path('login/', django_security_keys.views.basic_login, name="login"),
    path('logout/', django_security_keys.views.basic_logout, name="logout"),
    path('security-keys/', include( ('django_security_keys.urls', 'django_security_keys'), namespace="security-keys"))
]
```

## Add to custom login template

In order to integrate django-security-keys with your custom login view you need to include the following two lines in your template:

```
{% include "django-security-keys/static-includes.html" %}
{% include "django-security-keys/init.html" %}
```

## Set-up 2FA (Optionally)

### Settings 

Add `django_otp.plugins.otp_static`, `django_otp.plugins.otp_totp`, `django_otp.plugins.otp_email`, `two_factor` to your `INSTALLED_APPS`

```py
INSTALLED_APPS += [
  "django_otp.plugins.otp_static",
  "django_otp.plugins.otp_totp",
  "django_otp.plugins.otp_email",
  "two_factor",
]
```

Add `django_otp.middleware.OTPMiddleware` to your `MIDDLEWARE`.

```py
MIDDLEWARE += [
  "django_otp.middleware.OTPMiddleware",
]
```
Override templates.
```py
TEMPLATES += [
    {
        "DIRS": [BASE_DIR / "project/templates"],
    }
]
```

### urls

Edit `urls.py` to include `two-factor-auth`.

```py
from django.urls import path, include, re_path
from django_security_keys.ext.two_factor.views import LoginView

from two_factor.urls import urlpatterns as tf_urls

tf_urls[0][0] = re_path(
  route=r"^account/login/$",
  view=LoginView.as_view(),
  name="login",
)

urlpatterns += [
  path("two-factor-auth/", include(tf_urls, namespace="two-factor-auth")),
]
```