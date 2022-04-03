from django.contrib import admin
from core.models import CVE, FirmwareReference, Device, SysInfo

admin.site.site_header = admin.site.site_title = 'CVE Tracker Administration'
admin.site.index_title = 'Data administration'

@admin.register(CVE)
class CVEAdmin(admin.ModelAdmin):
    list_display = ('mitre_id', 'base_score', 'impact_score', 'exploitability_score', 'severity', 'urgency')


@admin.register(FirmwareReference)
class FirmwareReferenceAdmin(admin.ModelAdmin):
    list_display = ('cve', 'printable_firmware_version',)


@admin.register(Device)
class DeviceAdmin(admin.ModelAdmin):
    fields = ('serial_number', 'firmware_major', 'firmware_minor', 'firmware_build', 'vulnerable_cves',)
    readonly_fields = ('serial_number', 'last_seen', 'firmware_major', 'firmware_minor', 'firmware_build', 'vulnerable_cves',)
    list_display = ('serial_number', 'printable_firmware_version', 'last_seen',)

    def has_add_permission(self, request) -> bool:
        # this model is read-only for logging purposes
        return False
    
    def has_delete_permission(self, *args, **kwargs) -> bool:
        return False

@admin.register(SysInfo)
class SysInfoAdmin(admin.ModelAdmin):
    fields = ('name', 'admin_contact', 'cves_last_updated', 'platform_version', 'total_check_ins',)
    readonly_fields = ('name', 'total_check_ins',)
    list_display = ('admin_contact_email', 'cves_last_updated', 'platform_version', 'total_check_ins',)

    def admin_contact_email(self, obj):
        return obj.admin_contact.email

    def total_check_ins(self, obj):
        return Device.objects.count()

    def has_add_permission(self, request) -> bool:
        # only allow add if we don't have a record in the database
        if SysInfo.objects.first() is None:
            return True
        
        return False
    
    def has_delete_permission(self, *args, **kwargs) -> bool:
        return False
