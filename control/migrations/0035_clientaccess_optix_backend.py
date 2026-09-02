from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("control", "0034_clientaccess_activation_mode")]

    operations = [
        migrations.AddField(
            model_name="clientaccess",
            name="optix_backend",
            field=models.CharField(
                choices=[("warrior", "Warrior backend"), ("optix", "OPTIX backend")],
                default="warrior",
                help_text="Backend used by the OPTIX desktop app for this PC.",
                max_length=16,
            ),
        ),
        migrations.AddField(
            model_name="clientaccess",
            name="optix_backend_url",
            field=models.URLField(
                blank=True,
                default="",
                help_text="Required only when OPTIX backend is selected; must be its HTTPS base URL.",
            ),
        ),
    ]
