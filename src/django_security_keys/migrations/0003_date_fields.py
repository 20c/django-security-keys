# Generated by Django 3.2.9 on 2021-12-03 09:03

import datetime

from django.db import migrations, models
from django.utils.timezone import utc


class Migration(migrations.Migration):
    dependencies = [
        ("django_security_keys", "0002_attestation"),
    ]

    operations = [
        migrations.AddField(
            model_name="securitykey",
            name="created",
            field=models.DateTimeField(
                auto_now_add=True,
                default=datetime.datetime(2021, 12, 3, 9, 3, 14, 893775, tzinfo=utc),
            ),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name="securitykey",
            name="updated",
            field=models.DateTimeField(auto_now=True),
        ),
    ]
