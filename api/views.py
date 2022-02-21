from loguru import logger
from rest_framework import status as http_status
from rest_framework.throttling import UserRateThrottle, AnonRateThrottle
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.request import Request
from rest_framework.views import APIView
from rest_framework import viewsets
from rest_framework import permissions

from core.models import CVE, RiskProfile, FirmwareReference
from analytics.models import Device

from api.serializers import CVESerializer, RiskProfileSerializer, FirmwareReferenceSerializer
from analytics.serializers import DeviceSerializer

# DRF API Views
class CVEViewSet(viewsets.ModelViewSet):
    queryset = CVE.objects.all()
    serializer_class = CVESerializer
    permission_classes = [permissions.IsAuthenticatedOrReadOnly]

class RiskProfileViewSet(viewsets.ModelViewSet):
    queryset = RiskProfile.objects.all()
    serializer_class = RiskProfileSerializer
    permission_classes = [permissions.IsAuthenticatedOrReadOnly]

class FirmwareReferenceViewSet(viewsets.ModelViewSet):
    queryset = FirmwareReference.objects.all()
    serializer_class = FirmwareReferenceSerializer
    permission_classes = [permissions.IsAuthenticatedOrReadOnly]

class DeviceViewSet(viewsets.ModelViewSet):
    queryset = Device.objects.all()
    serializer_class = DeviceSerializer
    permission_classes = [permissions.IsAuthenticated]


# Device check-in endpoint
class DeviceCheckInView(APIView):
    throttle_classes = [UserRateThrottle]
    authentication_classes = [TokenAuthentication]



# Unauthenticated view to request system status
class StatusView(APIView):
    throttle_classes = [AnonRateThrottle]

    def get(self, request, format=None):
        system_ok = True
        status_msg = None

        # perform a simple database query to determine if system is operational
        # throttling prevents this from being abused to exhaust resources
        try:
            # we don't even really care what the result is, as long as the connection or query don't fail
            _test = CVE.objects.count()
        except Exception as ex:
            system_ok = False
            status_msg = 'Database not available'

        content = {
            'system_ok': system_ok,
            'status': status_msg
        }

        return Response(content, status=http_status.HTTP_200_OK)

class DummyView(APIView):
    authentication_classes = [TokenAuthentication]
    
    def get(self, request: Request, format=None):
        return Response({'endpoint': request.path}, status=http_status.HTTP_200_OK)