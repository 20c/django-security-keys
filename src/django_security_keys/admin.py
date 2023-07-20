from django.contrib import admin

from django_security_keys.models import SecurityKey


@admin.register(SecurityKey)
class SecurityKeyAdmin(admin.ModelAdmin):

    list_display = ("user", "name", "sign_count", "created", "updated")

    # user autocomplete
    autocomplete_fields = ("user",)

    search_fields = ("user__username", "name")


# Register your models here.
