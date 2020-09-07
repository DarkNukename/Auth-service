import sys
sys.path.append('../../')

from ..models import Application
from baseView import BaseView
import json
from django.conf import settings

access_token_ttl = settings.OAUTH2_ACCESS_TOKEN_TTL
refresh_token_ttl = settings.OAUTH2_REFRESH_TOKEN_TTL
access_token_size = settings.OAUTH2_ACCESS_TOKEN_SIZE
refresh_token_size = settings.OAUTH2_REFRESH_TOKEN_SIZE

class BaseOAuth2View(BaseView):

    def check_client_id(self):
        pass

    def check_client_secret(self):
        pass

    def create_authorization_code(self):
        pass

    def check_authorization_code(self):
        pass

class Oauth2UserAuth(BaseOAuth2View):
    pass

class Oauth2UserScopes(BaseOAuth2View):
    pass

class OAuth2View(BaseOAuth2View):
    pass
