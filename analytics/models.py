from django.db import models
from core.models import CVE

class VulnerableDevice(models.Model):
    class Meta:
        verbose_name = 'Vulnerable Device'

    serial_number = models.CharField(max_length=15)
    last_seen = models.DateTimeField(auto_now=False, auto_now_add=True)
    firmware_major = models.PositiveSmallIntegerField(blank=False, verbose_name='Firmware Major')
    firmware_minor = models.PositiveSmallIntegerField(blank=False, verbose_name='Firmware Minor')
    firmware_build = models.CharField(max_length=8, blank=False, verbose_name='Firmware Build')

    vulnerable_cves = models.ManyToManyField(CVE, verbose_name="Vulnerable CVEs")

    def printable_firmware_version(self):
        return f'{self.firmware_major:02}{self.firmware_minor}.{self.firmware_build}'
    printable_firmware_version.short_description = 'Firmware Version'

    def __str__(self):
        return self.serial_number 

