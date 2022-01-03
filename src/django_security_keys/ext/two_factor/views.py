import time

import two_factor.views
from django.contrib.auth import authenticate
from django.views.generic import FormView

from django_security_keys.ext.two_factor import forms
from django_security_keys.models import SecurityKey, SecurityKeyDevice


class DisableView(two_factor.views.DisableView):
    def dispatch(self, *args, **kwargs):
        self.success_url = "/"
        return FormView.dispatch(self, *args, **kwargs)


class LoginView(two_factor.views.LoginView):

    form_list = two_factor.views.LoginView.form_list + (
        ("security-key", forms.SecurityKeyDeviceValidation),
    )

    def has_security_key_step(self):
        if not self.get_user():
            return False

        # if a valid token was provided in the token step we dont need to
        # ask for additional 2FA via the security key
        token_step_data = self.storage.get_step_data("token")
        if token_step_data:
            return False

        return (
            len(SecurityKey.credentials(self.get_user().username, self.request.session))
            > 0
        )

    condition_dict = {
        "backup": two_factor.views.LoginView.has_backup_step,
        "token": two_factor.views.LoginView.has_token_step,
        "security-key": has_security_key_step,
    }

    def post(self, *args, **kwargs):
        request = self.request
        passwordless = self.attempt_passwordless_auth(request, **kwargs)
        if passwordless:
            return passwordless
        return super().post(*args, **kwargs)

    def attempt_passwordless_auth(self, request, **kwargs):

        """
        Prepares and attempts a passwordless authentication
        using a security key credential.

        This requires that the auth-username and credential
        fields are set in the POST data.

        This requires that the PasswordlessAuthenticationBackend is
        loaded.
        """

        if self.steps.current == "auth":

            credential = request.POST.get("credential")
            username = request.POST.get("auth-username")

            # support password-less login using webauthn
            if username and credential:

                try:
                    user = authenticate(
                        request, username=username, u2f_credential=credential
                    )
                    self.storage.reset()
                    self.storage.authenticated_user = user
                    self.storage.data["authentication_time"] = int(time.time())
                    form = self.get_form(
                        data=self.request.POST, files=self.request.FILES
                    )

                    if self.steps.current == self.steps.last:
                        return self.render_done(form, **kwargs)
                    return self.render_next_step(form)

                except Exception as exc:

                    self.passwordless_error = f"{exc}"
                    return self.render_goto_step("auth")

    def get_context_data(self, form, **kwargs):
        """
        If post request was rate limited the rate limit message
        needs to be communicated via the template context.
        """

        context = super().get_context_data(form, **kwargs)

        if "other_devices" in context:
            if self.has_security_key_step():
                context["other_devices"] += [self.get_security_key_device()]

        context["passwordless_error"] = getattr(self, "passwordless_error", None)

        if self.steps.current == "security-key":
            context["device"] = self.get_security_key_device()

        return context

    def get_security_key_device(self):

        """
        Will return a device object representing a webauthn
        choice if the user has any webauthn devices set up
        """

        if hasattr(self, "_security_key_device"):
            return self._security_key_device

        user = self.get_user()

        if not user or not user.webauthn_security_keys.exists():
            return None

        device = SecurityKeyDevice.require_for_user(user)
        device.user = user

        self._security_key_device = device

        return device

    def get_device(self, step=None):
        """
        Override this to can enable EmailDevice as a
        challenge device for one time passwords.
        """

        if not self.device_cache:
            challenge_device_id = self.request.POST.get("challenge_device", None)
            if challenge_device_id:

                # security key device
                device = self.get_security_key_device()
                if device and device.persistent_id == challenge_device_id:
                    self.device_cache = device
                    return self.device_cache

        return super().get_device(step=step)
