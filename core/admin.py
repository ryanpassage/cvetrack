from django.contrib import admin
from core.models import CVE, RiskProfile, FirmwareReference

admin.site.site_header = admin.site.site_title = 'CVE Tracker Administration'
admin.site.index_title = 'Data administration'

@admin.register(CVE)
class CVEAdmin(admin.ModelAdmin):
    list_fields = ('mitre_id', 'public_release_date', 'base_score',)


@admin.register(RiskProfile)
class RiskProfileAdmin(admin.ModelAdmin):
    pass

@admin.register(FirmwareReference)
class FirmwareReferenceAdmin(admin.ModelAdmin):
    pass

