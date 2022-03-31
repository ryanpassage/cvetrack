from django.urls import path, include
from rest_framework import routers
from . import views

router = routers.DefaultRouter()
router.register(r'cves', views.CVEViewSet)
router.register(r'firmware-references', views.FirmwareReferenceViewSet)
router.register(r'devices', views.DeviceViewSet)

# paths will resolve to /api/<endpoint>, e.g., /api/status/
urlpatterns = [
    path('', include(router.urls)),
    path('api-auth/', include('rest_framework.urls', namespace='rest_framework')),
    path('status/', views.StatusView.as_view()),

    # GET: return generic msg
    # POST: should receive fields: serial_number, ip_address, firmware
    path('check-in/', views.DeviceCheckInView.as_view()),

]