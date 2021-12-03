from django import forms


class RegisterKeyForm(forms.Form):
    name = forms.CharField(required=False)
    credential = forms.CharField(required=True, widget=forms.HiddenInput)
    passwordless_login = forms.BooleanField(required=False)


class LoginForm(forms.Form):
    username = forms.CharField(required=True)
    password = forms.CharField(required=False, widget=forms.PasswordInput)
