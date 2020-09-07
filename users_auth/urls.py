from django.urls import path

from .views.account_view import AccountsView, AccountView
from .views.auth_view import UserAuthView

urlpatterns = [
    path('auth/', UserAuthView.as_view()),
    path('accounts/', AccountsView.as_view()),
    path('account/<uuid:uuid>/', AccountView.as_view())
]