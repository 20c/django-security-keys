from django import forms
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _


class RegisterKeyForm(forms.Form):
    name = forms.CharField(required=False)
    credential = forms.CharField(required=True, widget=forms.HiddenInput)
    passkey_login = forms.BooleanField(required=False)
    password = forms.CharField(
        required=True,
        widget=forms.PasswordInput(attrs={"autocomplete": "current-password"}),
        label=_("Current Password"),
        help_text=_("Please enter your current password to add a security key."),
    )

    def __init__(self, *args, user=None, **kwargs):
        self.user = user
        super().__init__(*args, **kwargs)

    def clean_password(self):
        password = self.cleaned_data.get("password")
        if not password:
            raise ValidationError(_("Password is required."))

        if self.user and not self.user.check_password(password):
            raise ValidationError(_("Incorrect password. Please try again."))

        return password


class LoginForm(forms.Form):
    username = forms.CharField(required=False)
    password = forms.CharField(required=False, widget=forms.PasswordInput)
