# Generated by Django 4.0.2 on 2022-02-04 15:56

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0002_alter_cve_options_alter_firmwarereference_options_and_more'),
        ('analytics', '0002_alter_vulnerabledevice_options'),
    ]

    operations = [
        migrations.AlterField(
            model_name='vulnerabledevice',
            name='vulnerable_cves',
            field=models.ManyToManyField(to='core.CVE', verbose_name='Vulnerable CVEs'),
        ),
    ]
