from rest_framework import serializers
from analytics.models import VulnerableDevice

class VulnerableDeviceSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = VulnerableDevice
        fields = ('serial_number', 'last_seen', 'firmware_major', 'firmware_minor', 'firmware_build', 'vulnerable_cves',)
