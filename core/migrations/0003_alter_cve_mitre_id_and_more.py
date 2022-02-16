# Generated by Django 4.0.2 on 2022-02-12 21:29

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0002_alter_cve_options_alter_firmwarereference_options_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='cve',
            name='mitre_id',
            field=models.CharField(help_text='CVE number assigned by Mitre in full CVE-YEAR-##### format.', max_length=20, verbose_name='Mitre ID'),
        ),
        migrations.AlterField(
            model_name='firmwarereference',
            name='affected_build',
            field=models.CharField(help_text='Example: for FW 076.293, enter 293. If there are letters in the build, leave them out.', max_length=8, verbose_name='Affected Build'),
        ),
        migrations.AlterField(
            model_name='firmwarereference',
            name='affected_major',
            field=models.PositiveSmallIntegerField(help_text='Example: for FW 076.293, enter 7 (no leading 0)', verbose_name='Affected Major'),
        ),
        migrations.AlterField(
            model_name='firmwarereference',
            name='affected_minor',
            field=models.PositiveSmallIntegerField(help_text='Example: for FW 076.293, enter 6', verbose_name='Affected Minor'),
        ),
        migrations.AlterField(
            model_name='firmwarereference',
            name='cve',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='core.cve', verbose_name='CVE'),
        ),
        migrations.AlterField(
            model_name='firmwarereference',
            name='fixed_build',
            field=models.CharField(help_text='Example: for FW 076.293, enter 293. If there are letters in the build, leave them out.', max_length=8, verbose_name='Fixed Build'),
        ),
        migrations.AlterField(
            model_name='firmwarereference',
            name='fixed_major',
            field=models.PositiveSmallIntegerField(help_text='Example: for FW 076.293, enter 7 (no leading 0)', verbose_name='Fixed Major'),
        ),
        migrations.AlterField(
            model_name='firmwarereference',
            name='fixed_minor',
            field=models.PositiveSmallIntegerField(help_text='Example: for FW 076.293, enter 6', verbose_name='Fixed Minor'),
        ),
    ]