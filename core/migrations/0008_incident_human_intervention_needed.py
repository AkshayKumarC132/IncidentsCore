# Generated by Django 5.1.1 on 2024-10-26 17:40

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0007_client_team_member'),
    ]

    operations = [
        migrations.AddField(
            model_name='incident',
            name='human_intervention_needed',
            field=models.BooleanField(default=False),
        ),
    ]
