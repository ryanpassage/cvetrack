from rest_framework import serializers
from core.models import CVE, RiskProfile, FirmwareReference

class CVESerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = CVE
        fields = ('mitre_id', 'public_release_date', 'base_score', 'impact_score', 'exploitability_score', 'short_description',)

class RiskProfileSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = RiskProfile
        fields = ('cve', 'severity', 'urgency', 'summary', 'impact', 'support_url',)

class FirmwareReferenceSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = FirmwareReference
        fields = ('cve', 'rollup_versions', 'affected_major', 'affected_minor', 'affected_build', 'fixed_major', 'fixed_minor', 'fixed_build',)
