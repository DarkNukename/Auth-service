from django.urls import path

from .views.service_management_view import ServicesView, ServiceView
from .views.service_auth_view import ServiceAuthView

urlpatterns = [
    path('auth/', ServiceAuthView.as_view()),
    path('services/', ServicesView.as_view()),
    path('service/<uuid:uuid>/', ServiceView.as_view())
]