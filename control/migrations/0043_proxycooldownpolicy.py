from django.db import migrations, models


def create_default_policy(apps, schema_editor):
    apps.get_model("control", "ProxyCooldownPolicy").objects.using(
        schema_editor.connection.alias
    ).get_or_create(pk=1, defaults={"enabled": True, "revision": 0})


class Migration(migrations.Migration):
    dependencies = [("control", "0042_browsercatalogsnapshot")]

    operations = [
        migrations.CreateModel(
            name="ProxyCooldownPolicy",
            fields=[
                ("id", models.PositiveSmallIntegerField(default=1, editable=False, primary_key=True, serialize=False)),
                ("enabled", models.BooleanField(default=True)),
                ("revision", models.PositiveBigIntegerField(default=0)),
                ("updated_at", models.DateTimeField(blank=True, null=True)),
                ("updated_by", models.CharField(blank=True, default="", max_length=150)),
            ],
            options={
                "verbose_name": "Global proxy cooldown policy",
                "verbose_name_plural": "Global proxy cooldown policy",
                "constraints": [models.CheckConstraint(condition=models.Q(pk=1), name="proxy_cooldown_policy_singleton")],
            },
        ),
        migrations.RunPython(create_default_policy, migrations.RunPython.noop),
    ]
