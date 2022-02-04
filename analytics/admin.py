from django.contrib import admin
from analytics.models import VulnerableDevice

@admin.register(VulnerableDevice)
class VulnerableDeviceAdmin(admin.ModelAdmin):
    fields = ('serial_number', 'firmware_major', 'firmware_minor', 'firmware_build', 'vulnerable_cves',)
    readonly_fields = ('serial_number', 'last_seen', 'firmware_major', 'firmware_minor', 'firmware_build', 'vulnerable_cves',)
    list_display = ('serial_number', 'printable_firmware_version', 'last_seen',)

    def has_add_permission(self, request) -> bool:
        # this model is read-only for logging purposes
        return False
