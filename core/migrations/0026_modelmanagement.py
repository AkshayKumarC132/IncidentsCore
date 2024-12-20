# Generated by Django 5.1.1 on 2024-12-19 14:37

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0025_mlmodel'),
    ]

    operations = [
        migrations.CreateModel(
            name='ModelManagement',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=255)),
                ('size', models.IntegerField()),
                ('status', models.CharField(choices=[('Active', 'Active'), ('Inactive', 'Inactive')], default='Inactive', max_length=10)),
                ('uploaded_at', models.DateTimeField(auto_now_add=True)),
            ],
            options={
                'verbose_name': 'Model Management',
                'verbose_name_plural': 'Model Management',
                'db_table': 'model_management',
            },
        ),
    ]