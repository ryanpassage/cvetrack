from django.contrib import admin
from core.models import CVE, RiskProfile, FirmwareReference

admin.site.site_header = admin.site.site_title = 'CVE Tracker Administration'
admin.site.index_title = 'Data administration'

@admin.register(CVE)
class CVEAdmin(admin.ModelAdmin):
    list_display = ('mitre_id', 'public_release_date', 'base_score',)


@admin.register(RiskProfile)
class RiskProfileAdmin(admin.ModelAdmin):
    list_display = ('cve', 'severity', 'urgency',)


@admin.register(FirmwareReference)
class FirmwareReferenceAdmin(admin.ModelAdmin):
    list_display = ('cve', 'printable_affected_version', 'printable_fixed_version', 'rollup_versions',)


    
