# Generated by Django 4.0.2 on 2022-02-21 18:40

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0007_alter_cve_public_release_date'),
    ]

    operations = [
        migrations.AlterField(
            model_name='firmwarereference',
            name='affected_build',
            field=models.PositiveSmallIntegerField(help_text='Example: for FW 076.293, enter 293. If there are letters in the build, leave them out.', verbose_name='Affected Build'),
        ),
        migrations.AlterField(
            model_name='firmwarereference',
            name='fixed_build',
            field=models.PositiveSmallIntegerField(help_text='Example: for FW 076.293, enter 293. If there are letters in the build, leave them out.', verbose_name='Fixed Build'),
        ),
    ]