# Generated by Django 4.0.2 on 2022-02-04 15:42

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0001_initial'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='cve',
            options={'verbose_name': 'CVE'},
        ),
        migrations.AlterModelOptions(
            name='firmwarereference',
            options={'verbose_name': 'Firmware Reference'},
        ),
        migrations.AlterModelOptions(
            name='riskprofile',
            options={'verbose_name': 'Risk Profile'},
        ),
    ]
