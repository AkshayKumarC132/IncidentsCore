# Generated by Django 4.2 on 2024-11-20 12:15

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0013_screenrecording'),
    ]

    operations = [
        migrations.AddField(
            model_name='screenrecording',
            name='incident',
            field=models.IntegerField(null=True),
        ),
        migrations.AddField(
            model_name='screenrecording',
            name='is_recording',
            field=models.BooleanField(default=False),
        ),
        migrations.AlterField(
            model_name='screenrecording',
            name='file_path',
            field=models.CharField(max_length=255, null=True),
        ),
    ]