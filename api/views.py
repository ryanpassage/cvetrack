import re
from loguru import logger
from rest_framework import status as http_status
from rest_framework.throttling import UserRateThrottle, AnonRateThrottle
from rest_framework.permissions import IsAuthenticatedOrReadOnly
from rest_framework.authentication import TokenAuthentication
from rest_framework.response import Response
from rest_framework.request import Request
from rest_framework.views import APIView
from rest_framework import permissions
from rest_framework import viewsets
from django.contrib.auth.models import AnonymousUser

from core.models import CVE, FirmwareReference, Device, SysInfo
from api.serializers import CVESerializer, FirmwareReferenceSerializer, DeviceSerializer


# utilities
class FirmwareParser:
    def __init__(self, firmware=None):
        if firmware is None:
            return
        
        self.firmware = firmware
        self.major = 0
        self.minor = 0
        self.build = 0
        self.full_version = ''

        if firmware is None:
            self.parsed = False
        else:
            self.parsed = self._parse()

    def _parse(self):
        if not self.firmware:
            return False
        
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
            self.full_version = f'{self.major}.{self.minor}.{self.build}'
            return True
        else:
            return False


    def formatted_version(self):
        return f'{self.major}.{self.minor}.{self.build}'


# DRF API Views
class CVEViewSet(viewsets.ModelViewSet):
    queryset = CVE.objects.all()
    serializer_class = CVESerializer
    permission_classes = [permissions.IsAuthenticated]

class FirmwareReferenceViewSet(viewsets.ModelViewSet):
    queryset = FirmwareReference.objects.all()
    serializer_class = FirmwareReferenceSerializer
    permission_classes = [permissions.IsAuthenticated]

class DeviceViewSet(viewsets.ModelViewSet):
    queryset = Device.objects.all()
    serializer_class = DeviceSerializer
    permission_classes = [permissions.IsAuthenticated]


# Device check-in endpoint
class DeviceCheckInView(APIView):
    throttle_classes = [AnonRateThrottle]
    # this API endpoint is not authenticated because devices need to check in from everywhere
    # uncomment the following lines to require token authentication
    # authentication_classes = [TokenAuthentication]
    # permission_classes = [permissions.IsAuthenticated]

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
        # default device type is Claiborne/Moja
        # TODO: integrate with other data sources to determine device type
        device_type = FirmwareReference.DeviceType.XML

        logger.info(f'Checking CVEs for FW {parser.formatted_version()}')
        major_refs = FirmwareReference.objects.filter(fixed_major__gt=parser.major) # automatically vulnerable to all of these
        logger.info(f'\tMajor Refs: {major_refs.count()}')
        major_minor_refs = FirmwareReference.objects.filter(fixed_major=parser.major, fixed_minor__gt=parser.minor) # CVEs for current major and minors LT current
        logger.info(f'\tMajor+Minor Refs: {major_minor_refs.count()}')
        build_refs = FirmwareReference.objects.filter(fixed_major=parser.major, fixed_minor=parser.minor, fixed_build__gt=parser.build)
        logger.info(f'\tMajor+Minor+Build Refs: {build_refs.count()}')

        # combine results in to one queryset (does not preserve order, which is fine)
        refs = major_refs | major_minor_refs | build_refs
        logger.success(f'Total CVEs: {refs.count()}')

        cves = []
        for ref in refs:
            logger.debug(f'Ref: {ref}')
            
            serializer = CVESerializer(ref.cve)
            
            if len(serializer.data.items()) > 0:
                device.vulnerable_cves.add(ref.cve)
                cves.append(serializer.data)

        if len(cves) > 0:
            content.update({'has_vulnerabilities': True, 'cves': cves})

        return Response(content, status=http_status.HTTP_200_OK)            


# Unauthenticated view to request system status
class StatusView(viewsets.ViewSet):
    throttle_classes = [AnonRateThrottle, UserRateThrottle]
    permission_classes = [IsAuthenticatedOrReadOnly]

    # was get previously as an APIView
    def list(self, request, format=None):
        response = {
            'status_ok': True,
            'authenticated': False,
        }

        if str(request.user) != 'AnonymousUser':
            # user is logged in, provide additional information
            response['authenticated'] = True
            response.update({'user': str(request.user)})

            sysinfo = SysInfo.objects.first()

            response.update({'admin_contact': f'{sysinfo.admin_contact.first_name} {sysinfo.admin_contact.last_name} <{sysinfo.admin_contact.email}>'})
            response.update({'cves_last_updated': sysinfo.cves_last_updated})
            response.update({'platform_version': sysinfo.platform_version})
            response.update({'total_check_ins': Device.objects.count()})

        return Response(response, status=http_status.HTTP_200_OK)


class DummyView(APIView):
    authentication_classes = [TokenAuthentication]
    
    def get(self, request: Request, format=None):
        return Response({'endpoint': request.path}, status=http_status.HTTP_200_OK)