from operator import itemgetter
from django.db import models
from core.models import CVE

# Create your models here.
class VulnerableDevice(models.Model):
    serial_number = models.CharField(max_length=15)
    last_seen = models.DateTimeField(auto_now=False, auto_now_add=True)
    firmware_major = models.PositiveSmallIntegerField(blank=False, verbose_name='Firmware Major')
    firmware_minor = models.PositiveSmallIntegerField(blank=False, verbose_name='Firmware Minor')
    firmware_build = models.CharField(max_length=8, blank=False, verbose_name='Firmware Build')

    vulnerable_cves = models.ManyToManyField(CVE)

    def printable_firmware_version(self):
        return f'{self.firmware_major:02}{self.firmware_minor}.{self.firmware_build}'

    def __str__(self):
        return f'{self.serial_number} ({self.printable_firmware_version()})' 
