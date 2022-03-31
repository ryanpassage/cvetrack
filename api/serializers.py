from rest_framework import serializers
from core.models import CVE, FirmwareReference, Device

class CVESerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = CVE
        fields = ('mitre_id', 'public_release_date', 'base_score', 'impact_score', 'exploitability_score', 'short_description', 'support_url', 'severity', 'urgency',)

class FirmwareReferenceSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = FirmwareReference
        fields = ('cve', 'rollup_versions', 'affected_major', 'affected_minor', 'affected_build', 'fixed_major', 'fixed_minor', 'fixed_build',)

class DeviceSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = Device
        fields = ('serial_number', 'last_seen', 'firmware_major', 'firmware_minor', 'firmware_build', 'vulnerable_cves',)