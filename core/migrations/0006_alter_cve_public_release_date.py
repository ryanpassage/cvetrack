# Generated by Django 4.0.2 on 2022-02-19 16:10

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0005_remove_riskprofile_support_url_cve_support_url'),
    ]

    operations = [
        migrations.AlterField(
            model_name='cve',
            name='public_release_date',
            field=models.DateField(blank=True, help_text='CVE release date'),
        ),
    ]