from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("control", "0039_backfill_desktop_client_identity")]

    operations = [
        migrations.AlterField(
            model_name="clientaccess",
            name="desktop_remote_action",
            field=models.CharField(
                blank=True,
                choices=[
                    ("", "No remote action"),
                    ("uninstall", "Uninstall OPTIX"),
                    ("migrate_optix", "Replace legacy desktop with OPTIX"),
                ],
                default="",
                help_text="Pending command delivered to this authorized OPTIX installation.",
                max_length=24,
            ),
        ),
    ]
