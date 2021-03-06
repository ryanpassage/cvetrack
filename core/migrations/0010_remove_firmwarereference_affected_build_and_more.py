# Generated by Django 4.0.2 on 2022-03-31 00:43

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0009_device'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='firmwarereference',
            name='affected_build',
        ),
        migrations.RemoveField(
            model_name='firmwarereference',
            name='affected_major',
        ),
        migrations.RemoveField(
            model_name='firmwarereference',
            name='affected_minor',
        ),
        migrations.RemoveField(
            model_name='firmwarereference',
            name='rollup_versions',
        ),
        migrations.AddField(
            model_name='cve',
            name='severity',
            field=models.PositiveSmallIntegerField(choices=[(1, '(1) Least Concern'), (2, '(2) Some Concern'), (3, '(3) Moderate Concern'), (4, '(4) High Concern'), (5, '(5) CRITICAL')], null=True),
        ),
        migrations.AddField(
            model_name='cve',
            name='urgency',
            field=models.PositiveSmallIntegerField(choices=[(1, '(1) Least Concern'), (2, '(2) Some Concern'), (3, '(3) Moderate Concern'), (4, '(4) High Concern'), (5, '(5) CRITICAL')], null=True),
        ),
        migrations.DeleteModel(
            name='RiskProfile',
        ),
    ]
