# Generated by Django 4.0.2 on 2022-02-04 14:37

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='CVE',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('mitre_id', models.CharField(help_text='CVE number assigned by Mitre', max_length=20, verbose_name='Mitre ID')),
                ('public_release_date', models.DateField(help_text='CVE release date')),
                ('base_score', models.DecimalField(blank=True, decimal_places=1, max_digits=3, verbose_name='CVSS Base Score')),
                ('impact_score', models.DecimalField(blank=True, decimal_places=1, help_text='Impact Subscore from Mitre', max_digits=3, verbose_name='Impact Subscore')),
                ('exploitability_score', models.DecimalField(blank=True, decimal_places=1, help_text='Exploitability Subscore from Mitre', max_digits=3, verbose_name='Exploitability Subscore')),
            ],
        ),
        migrations.CreateModel(
            name='RiskProfile',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('severity', models.PositiveSmallIntegerField(choices=[(1, '(1) Least Concern'), (2, '(2) Some Concern'), (3, '(3) Moderate Concern'), (4, '(4) High Concern'), (5, '(5) CRITICAL')])),
                ('urgency', models.PositiveSmallIntegerField(choices=[(1, '(1) Least Concern'), (2, '(2) Some Concern'), (3, '(3) Moderate Concern'), (4, '(4) High Concern'), (5, '(5) CRITICAL')])),
                ('summary', models.TextField(blank=True)),
                ('impact', models.TextField(blank=True)),
                ('support_url', models.URLField()),
                ('cve', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='core.cve')),
            ],
        ),
        migrations.CreateModel(
            name='FirmwareReference',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('rollup_versions', models.BooleanField(default=True, help_text='Enable to include all previous firmware versions in this profile.', verbose_name='Roll-Up Previous Versions')),
                ('affected_major', models.PositiveSmallIntegerField(verbose_name='Affected Major')),
                ('affected_minor', models.PositiveSmallIntegerField(verbose_name='Affected Minor')),
                ('affected_build', models.CharField(max_length=8, verbose_name='Affected Build')),
                ('fixed_major', models.PositiveSmallIntegerField(verbose_name='Fixed Major')),
                ('fixed_minor', models.PositiveSmallIntegerField(verbose_name='Fixed Minor')),
                ('fixed_build', models.CharField(max_length=8, verbose_name='Fixed Build')),
                ('cve', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='core.cve')),
            ],
        ),
    ]