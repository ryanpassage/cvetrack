from django.urls import path
from . import views

# paths will resolve to /api/<endpoint>, e.g., /api/status/
urlpatterns = [
    path('status/', views.StatusView.as_view()),

    # GET: return generic msg
    # POST: should receive fields: serial_number, ip_address, firmware
    path('check-in/', views.DummyView.as_view())
    
]