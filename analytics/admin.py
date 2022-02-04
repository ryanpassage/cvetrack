from django.contrib import admin
from analytics.models import VulnerableDevice

@admin.register(VulnerableDevice)
class VulnerableDeviceAdmin(admin.ModelAdmin):
    pass

