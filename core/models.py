from django.db import models
from django.utils.translation import gettext_lazy as _
from django.conf import settings
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.contrib.auth.models import User
from rest_framework.authtoken.models import Token

@receiver(post_save, sender=settings.AUTH_USER_MODEL)
def create_auth_token(sender, instance=None, created=False, **kwargs):
    if created:
        # auto-generate a token for new user accounts
        Token.objects.create(user=instance)

# Create your models here.
class CVE(models.Model):
    class Rating(models.IntegerChoices):
        LEAST_CONCERN = 1, _('(1) Least Concern')
        SOME_CONCERN = 2, _('(2) Some Concern')
        MODERATE = 3, _('(3) Moderate Concern')
        HIGH = 4, _('(4) High Concern')
        CRITICAL = 5, _('(5) CRITICAL')

    class Meta:
        verbose_name = 'CVE'

    mitre_id = models.CharField(max_length=20, blank=False, verbose_name='Mitre ID', help_text='CVE number assigned by Mitre in full CVE-YEAR-##### format.')
    public_release_date = models.DateField(blank=True, null=True, help_text='CVE release date')
    base_score = models.DecimalField(blank=True, max_digits=3, decimal_places=1, verbose_name='CVSS Base Score')
    impact_score = models.DecimalField(blank=True, max_digits=3, decimal_places=1, verbose_name='Impact Subscore', help_text='Impact Subscore from Mitre')
    exploitability_score = models.DecimalField(blank=True, max_digits=3, decimal_places=1, verbose_name='Exploitability Subscore', help_text='Exploitability Subscore from Mitre')
    short_description = models.TextField(blank=True, help_text='Provide a one-line description for this CVE.')
    support_url = models.URLField()

    # brought over from risk profile
    severity = models.PositiveSmallIntegerField(null=True, blank=False, choices=Rating.choices)
    urgency = models.PositiveSmallIntegerField(null=True, blank=False, choices=Rating.choices)

    def __str__(self):
        return self.mitre_id


class FirmwareReference(models.Model):
    class Meta:
        verbose_name = 'Firmware Reference'
        
    cve = models.ForeignKey(CVE, on_delete=models.CASCADE, verbose_name='CVE')

    # Based on firmware release naming convention documentation from FW PE:
    # https://lexmarkad.sharepoint.com/:w:/r/sites/firmware_software_product_engineering/_layouts/15/Doc.aspx?sourcedoc=%7B586CBABA-10E4-4913-ACF9-F39378EEFE9F%7D&file=Firmware%20Release%20Naming%20Convention.docx&action=default&mobileredirect=true&cid=1a3cc8f8-c89f-4300-848b-26772e1e2062
    fixed_major = models.PositiveSmallIntegerField(blank=False, verbose_name='Fixed Major', help_text='Example: for FW 076.293, enter 7 (no leading 0)')
    fixed_minor = models.PositiveSmallIntegerField(blank=False, verbose_name='Fixed Minor', help_text='Example: for FW 076.293, enter 6')
    fixed_build = models.PositiveSmallIntegerField(blank=False, verbose_name='Fixed Build', help_text='Example: for FW 076.293, enter 293. If there are letters in the build, leave them out.')

    def printable_firmware_version(self):
        return f'{self.major:02}.{self.minor}.{self.build}'
    
    def __str__(self):
        incl_prev = ' and previous' if self.rollup_versions is True else ' only'
        return f'{self.cve}: {self.printable_fixed_version()}{incl_prev}'


class Device(models.Model):
    class Meta:
        verbose_name = 'Device'

    serial_number = models.CharField(max_length=15)
    model = models.CharField(max_length=50)
    last_seen = models.DateTimeField(auto_now=False, auto_now_add=True)
    firmware_major = models.PositiveSmallIntegerField(blank=False, verbose_name='Firmware Major')
    firmware_minor = models.PositiveSmallIntegerField(blank=False, verbose_name='Firmware Minor')
    firmware_build = models.CharField(max_length=8, blank=False, verbose_name='Firmware Build')

    vulnerable_cves = models.ManyToManyField(CVE, verbose_name="Vulnerable CVEs", blank=True)

    def printable_firmware_version(self):
        return f'{self.firmware_major:02}.{self.firmware_minor}.{self.firmware_build}'
    printable_firmware_version.short_description = 'Firmware Version'

    def __str__(self):
        return self.serial_number 

class SysInfo(models.Model):
    admin_contact = models.ForeignKey(User, on_delete=models.DO_NOTHING, verbose_name='Current Admin User')
    cves_last_updated = models.DateTimeField(auto_now=False, auto_now_add=False, blank=False, verbose_name='CVE Data Last Updated')
    platform_version = models.CharField(max_length=25, blank=False, verbose_name='CVE Tracking Platform Version')

