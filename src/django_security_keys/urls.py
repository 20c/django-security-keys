from django.urls import path

import django_security_keys.views as views

urlpatterns = [
    path("manage/", views.manage_keys, name="manage-keys"),
    path(
        "request-registration/", views.request_registration, name="request-registration"
    ),
    path(
        "request-authentication/",
        views.request_authentication,
        name="request-authentication",
    ),
    path("register/", views.register_security_key, name="register"),
    path("register-form/", views.register_security_key_form, name="register-form"),
    path("authenticate/", views.verify_authentication, name="authenticate"),
    path("decommission/", views.remove_security_key, name="decommission"),
    path(
        "decommission-form/", views.remove_security_key_form, name="decommission-form"
    ),
]
