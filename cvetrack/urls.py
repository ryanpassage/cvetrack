from django.contrib import admin
from django.urls import path, include
from core import views as core_views

urlpatterns = [
    path('admin/', admin.site.urls),

    # non-API endpoints
    path('', core_views.index),

    path('api/', include('api.urls'))
]
