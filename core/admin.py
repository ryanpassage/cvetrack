from django.contrib import admin
from core.models import CVE, RiskProfile, FirmwareReference, Device

admin.site.site_header = admin.site.site_title = 'CVE Tracker Administration'
admin.site.index_title = 'Data administration'

@admin.register(CVE)
class CVEAdmin(admin.ModelAdmin):
    list_display = ('mitre_id', 'base_score', 'impact_score', 'exploitability_score',)


@admin.register(RiskProfile)
class RiskProfileAdmin(admin.ModelAdmin):
    list_display = ('cve', 'severity', 'urgency',)


@admin.register(FirmwareReference)
class FirmwareReferenceAdmin(admin.ModelAdmin):
    list_display = ('cve', 'printable_affected_version', 'printable_fixed_version', 'rollup_versions',)


@admin.register(Device)
class DeviceAdmin(admin.ModelAdmin):
    fields = ('serial_number', 'firmware_major', 'firmware_minor', 'firmware_build', 'vulnerable_cves',)
    readonly_fields = ('serial_number', 'last_seen', 'firmware_major', 'firmware_minor', 'firmware_build', 'vulnerable_cves',)
    list_display = ('serial_number', 'printable_firmware_version', 'last_seen',)

    def has_add_permission(self, request) -> bool:
        # this model is read-only for logging purposes
        return False