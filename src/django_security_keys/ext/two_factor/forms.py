from __future__ import annotations

from typing import Any

import django.forms as forms
from django.core.exceptions import ValidationError
from django.core.handlers.wsgi import WSGIRequest
from django.utils.translation import gettext as _

from django_security_keys.models import SecurityKey


class SecurityKeyDeviceValidation(forms.Form):

    credential = forms.CharField(widget=forms.HiddenInput())
    credential.widget.attrs.update({"type": "hidden"})

    def __init__(
        self,
        request: WSGIRequest | None = None,
        device: Any | None = None,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        self.request = request
        self.device = device
        super().__init__(*args, **kwargs)

    def clean(self):

        super().clean()

        if self.device.authenticated:
            return self.cleaned_data

        credential = self.cleaned_data["credential"]

        try:
            SecurityKey.verify_authentication(
                self.device.user.username, self.request.session, credential
            )
            self.device.authenticated = True
        except Exception:
            raise ValidationError(_("Security key authentication failed"))

        return self.cleaned_data
