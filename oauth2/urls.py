from django.urls import path

from .views.app_views import ApplicationsView, ApplicationView


urlpatterns = [
    # path('auth/', ServiceAuthView.as_view()),
    path('applications/', ApplicationsView.as_view()),
    path('application/<uuid:uuid>/', ApplicationView.as_view())
]