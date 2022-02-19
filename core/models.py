from django.db import models
from django.utils.translation import gettext_lazy as _
from django.conf import settings
from django.db.models.signals import post_save
from django.dispatch import receiver
from rest_framework.authtoken.models import Token

@receiver(post_save, sender=settings.AUTH_USER_MODEL)
def create_auth_token(sender, instance=None, created=False, **kwargs):
    if created:
        # auto-generate a token for new user accounts
        Token.objects.create(user=instance)

# Create your models here.
class CVE(models.Model):
    class Meta:
        verbose_name = 'CVE'

    mitre_id = models.CharField(max_length=20, blank=False, verbose_name='Mitre ID', help_text='CVE number assigned by Mitre in full CVE-YEAR-##### format.')
    public_release_date = models.DateField(blank=False, help_text='CVE release date')
    base_score = models.DecimalField(blank=True, max_digits=3, decimal_places=1, verbose_name='CVSS Base Score')
    impact_score = models.DecimalField(blank=True, max_digits=3, decimal_places=1, verbose_name='Impact Subscore', help_text='Impact Subscore from Mitre')
    exploitability_score = models.DecimalField(blank=True, max_digits=3, decimal_places=1, verbose_name='Exploitability Subscore', help_text='Exploitability Subscore from Mitre')
    short_description = models.TextField(blank=True, help_text='Provide a one-line description for this CVE.')
    support_url = models.URLField()


    def __str__(self):
        return self.mitre_id

class RiskProfile(models.Model):
    class Rating(models.IntegerChoices):
        LEAST_CONCERN = 1, _('(1) Least Concern')
        SOME_CONCERN = 2, _('(2) Some Concern')
        MODERATE = 3, _('(3) Moderate Concern')
        HIGH = 4, _('(4) High Concern')
        CRITICAL = 5, _('(5) CRITICAL')

    class Meta:
        verbose_name = 'Risk Profile'
    
    cve = models.ForeignKey(CVE, on_delete=models.CASCADE)

    # 1-5 scale, 1 being least concern, 5 being critical
    severity = models.PositiveSmallIntegerField(choices=Rating.choices)
    urgency = models.PositiveSmallIntegerField(choices=Rating.choices)

    summary = models.TextField(blank=True)
    impact = models.TextField(blank=True)

    def __str__(self):
        return f'{self.cve} S:{self.severity} U:{self.urgency}'

class FirmwareReference(models.Model):
    class Meta:
        verbose_name = 'Firmware Reference'
        
    cve = models.ForeignKey(CVE, on_delete=models.CASCADE, verbose_name='CVE')
    rollup_versions = models.BooleanField(default=True, verbose_name='Roll-Up Previous Versions', help_text='Enable to include all previous firmware versions in this profile.')

    # Based on firmware release naming convention documentation from FW PE:
    # https://lexmarkad.sharepoint.com/:w:/r/sites/firmware_software_product_engineering/_layouts/15/Doc.aspx?sourcedoc=%7B586CBABA-10E4-4913-ACF9-F39378EEFE9F%7D&file=Firmware%20Release%20Naming%20Convention.docx&action=default&mobileredirect=true&cid=1a3cc8f8-c89f-4300-848b-26772e1e2062
    affected_major = models.PositiveSmallIntegerField(blank=False, verbose_name='Affected Major', help_text='Example: for FW 076.293, enter 7 (no leading 0)')
    affected_minor = models.PositiveSmallIntegerField(blank=False, verbose_name='Affected Minor', help_text='Example: for FW 076.293, enter 6')
    affected_build = models.CharField(max_length=8, blank=False, verbose_name='Affected Build', help_text='Example: for FW 076.293, enter 293. If there are letters in the build, leave them out.')
    fixed_major = models.PositiveSmallIntegerField(blank=False, verbose_name='Fixed Major', help_text='Example: for FW 076.293, enter 7 (no leading 0)')
    fixed_minor = models.PositiveSmallIntegerField(blank=False, verbose_name='Fixed Minor', help_text='Example: for FW 076.293, enter 6')
    fixed_build = models.CharField(max_length=8, blank=False, verbose_name='Fixed Build', help_text='Example: for FW 076.293, enter 293. If there are letters in the build, leave them out.')

    def printable_firmware_version(self, which='affected'):
        major = getattr(self, f'{which}_major')
        minor = getattr(self, f'{which}_minor')
        build = getattr(self, f'{which}_build')

        return f'{major:02}{minor}.{build}'

    def printable_affected_version(self):
        return self.printable_firmware_version(which='affected')
    printable_affected_version.short_description = 'Affected Version'
    
    def printable_fixed_version(self):
        return self.printable_firmware_version(which='fixed')
    printable_fixed_version.short_description = 'Fixed Version'

    def __str__(self):
        incl_prev = ' and previous' if self.rollup_versions is True else ' only'
        return f'{self.cve}: {self.printable_firmware_version()}{incl_prev}'