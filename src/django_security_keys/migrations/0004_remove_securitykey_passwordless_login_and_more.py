from django.db import migrations, models


def migrate_passwordless_login_to_passkey_login(apps, schema_editor):
    model = apps.get_model("django_security_keys", "SecurityKey")
    try:
        model._meta.get_field("updated").auto_now = False
        for key in model.objects.all():
            key.passkey_login = key.passwordless_login
            key.save(update_fields=["passkey_login"])
    finally:
        model._meta.get_field("updated").auto_now = False


class Migration(migrations.Migration):
    dependencies = [
        ("django_security_keys", "0003_date_fields"),
    ]

    operations = [
        migrations.AddField(
            model_name="securitykey",
            name="passkey_login",
            field=models.BooleanField(
                default=False, help_text="User has enabled this key for passkey login"
            ),
        ),
        migrations.RunPython(migrate_passwordless_login_to_passkey_login),
        migrations.RemoveField(
            model_name="securitykey",
            name="passwordless_login",
        ),
    ]
