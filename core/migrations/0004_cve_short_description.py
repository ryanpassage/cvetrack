# Generated by Django 4.0.2 on 2022-02-16 02:18

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0003_alter_cve_mitre_id_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='cve',
            name='short_description',
            field=models.TextField(blank=True, help_text='Provide a one-line description for this CVE.'),
        ),
    ]
