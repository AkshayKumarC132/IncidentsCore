# Generated by Django 5.1.1 on 2024-12-06 15:37

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0021_jiraticket_user_alter_jiraticket_unique_together'),
    ]

    operations = [
        migrations.AddField(
            model_name='jiraticket',
            name='confidence_score',
            field=models.FloatField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='jiraticket',
            name='predicted_agent',
            field=models.CharField(blank=True, max_length=50, null=True),
        ),
    ]
