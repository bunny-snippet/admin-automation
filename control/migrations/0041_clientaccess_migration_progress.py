from django.db import migrations, models


def backfill_progress(apps, schema_editor):
    ClientAccess = apps.get_model("control", "ClientAccess")
    ClientAccess.objects.filter(
        desktop_remote_action="migrate_optix",
        desktop_remote_action_acknowledged_at__isnull=False,
    ).update(
        desktop_remote_action_phase="completed",
        desktop_remote_action_progress=100,
        desktop_remote_action_status_message="OPTIX migration completed successfully.",
        desktop_remote_action_error="",
        desktop_remote_action_status_at=models.F("desktop_remote_action_acknowledged_at"),
    )
    ClientAccess.objects.filter(
        desktop_remote_action="migrate_optix",
        desktop_remote_action_acknowledged_at__isnull=True,
    ).update(
        desktop_remote_action_phase="queued",
        desktop_remote_action_progress=0,
        desktop_remote_action_status_message="Migration command is waiting for the PC.",
        desktop_remote_action_error="",
        desktop_remote_action_status_at=models.F("desktop_remote_action_requested_at"),
    )


class Migration(migrations.Migration):
    dependencies = [("control", "0040_clientaccess_optix_migration_action")]

    operations = [
        migrations.AddField(
            model_name="clientaccess",
            name="desktop_remote_action_phase",
            field=models.CharField(blank=True, default="", max_length=40),
        ),
        migrations.AddField(
            model_name="clientaccess",
            name="desktop_remote_action_progress",
            field=models.PositiveSmallIntegerField(default=0),
        ),
        migrations.AddField(
            model_name="clientaccess",
            name="desktop_remote_action_status_message",
            field=models.TextField(blank=True, default=""),
        ),
        migrations.AddField(
            model_name="clientaccess",
            name="desktop_remote_action_error",
            field=models.TextField(blank=True, default=""),
        ),
        migrations.AddField(
            model_name="clientaccess",
            name="desktop_remote_action_status_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.RunPython(backfill_progress, migrations.RunPython.noop),
    ]
