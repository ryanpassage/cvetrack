import re
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

from core.models import CVE, RiskProfile, FirmwareReference, Device
from api.serializers import CVESerializer, RiskProfileSerializer, FirmwareReferenceSerializer, DeviceSerializer


# utilities
class FirmwareParser:
    def __init__(self, firmware=None):
        if firmware is None:
            return
        
        self.firmware = firmware
        self.major = 0
        self.minor = 0
        self.build = 0

        self.parsed = self._parse()

    def _parse(self):
        if not self.firmware:
            return None
        
        # example firmware version formats:
        # - CSTAT.075.281
        #   - segments: 3, major_minor_segment: 2, build_segment: 3
        # -	LW63.SB7.P725
        #   - segments: 3, major_minor: 1, build: 3
        # - CXNZJ.20211215121539
        #   - segments: 2, major_minor: 0, build: 0

        # strip out alpha characters, they are ignored
        stripped = re.sub('[a-zA-Z]', '', self.firmware)
        parts = stripped.split('.')

        if len(parts) < 3:
            # 2-part fw versions aren't used and may indicate development version
            # TODO: revise when new FW numbering scheme goes in to effect w/ YMD parts
            # all the defaults already indicate this is not a usable firmware version
            return False
        
        self.build = int(parts[2])

        # find the major and minor versions
        for i in range(0, 2):
            part = parts[i]

            if part == '':
                continue
            
            if part.startswith('0'):
                part = part[1:]
            
            if len(part) == 1:
                if self.major == 0:
                    self.major = int(part)
            
            if len(part) == 2:
                self.major = int(part[0])
                self.minor = int(part[1])
        
        if self.major > 0:
            return True
        else:
            return False


    def formatted_version(self):
        return f'{self.major}.{self.minor}.{self.build}'


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
    #authentication_classes = [TokenAuthentication]

    def get(self, request: Request):
        return Response({'error': True, 'reason': 'This endpoint accepts POST parameters only.'}, status=http_status.HTTP_400_BAD_REQUEST)

    @logger.catch
    def post(self, request: Request):
        content = {
            'error': False, 
            'has_vulnerabilities': False,
        }

        # if has_vulnerabilities is True:
        # content['cves'] = [{'cve_num': 'CVE-2022-12345', etc..}, {'cve_num': 'CVE-2022-78900', etc...},]

        '''
            Expected data from request:
            - serial_num
            - model
            - firmware
        '''
        serial_num = request.data.get('serial_num', None)
        model = request.data.get('model', None)
        firmware = request.data.get('firmware', None)

        if serial_num is None or model is None or firmware is None:
            content.update({'error': True, 'reason': 'Request data contains invalid values', 'request_data': request.data})
            return Response(content, status=http_status.HTTP_400_BAD_REQUEST)
        
        parser = FirmwareParser(firmware)

        if not parser.parsed or parser.major == 0:
            content.update({'error': True, 'reason': 'Unable to parse provided firmware version', 'request_data': request.data})
            return Response(content, status=http_status.HTTP_400_BAD_REQUEST)

        device = Device(serial_number=serial_num, model=model, firmware_major=parser.major, firmware_minor=parser.minor, firmware_build=parser.build)

        try:
            device.save()
        except Exception as ex:
            content.update({'error': True, 'reason': f'Database error: {ex}', 'request_data': request.data})
            return Response(content, status=http_status.HTTP_500_INTERNAL_SERVER_ERROR)

        # find vulnerabilities by firmware reference
        # TODO:
        # This needs to be smarter about major/minor/build checks
        # example: fw 8.3.201 is vulnerable to a CVE
        # the below query will miss version 7.5.100 because minor version will fail the chained "AND" LTE check
        refs = FirmwareReference.objects.filter(affected_major__lte=parser.major, affected_minor__lte=parser.minor, affected_build__lte=parser.build)
        cves = []

        for ref in refs:
            logger.debug(f'Ref: {ref}')
            serializer = CVESerializer(ref.cve)
            
            if len(serializer.data.items()) > 0:
                cves.append(serializer.data)

        if len(cves) > 0:
            content.update({'has_vulnerabilities': True, 'cves': cves})

        return Response(content, status=http_status.HTTP_200_OK)            


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