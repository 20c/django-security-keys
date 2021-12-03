from django.contrib import admin

from django_security_keys.models import SecurityKey


@admin.register(SecurityKey)
class SecurityKeyAdmin(admin.ModelAdmin):

    list_display = ("user", "name", "sign_count", "created", "updated")


# Register your models here.
