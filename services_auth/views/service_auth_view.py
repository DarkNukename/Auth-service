import sys

sys.path.append('../../')

from ..models import Services
from baseView import BaseView
import json
from django.conf import settings
import redis

access_token_ttl = settings.SERVICES_ACCESS_TOKEN_TTL
refresh_token_ttl = settings.SERVICES_REFRESH_TOKEN_TTL
access_token_size = settings.SERVICES_ACCESS_TOKEN_SIZE
refresh_token_size = settings.SERVICES_REFRESH_TOKEN_SIZE


class BaseServiceAuthView(BaseView):
    def data_analizer(self, data):
        if 'access_token' in data:
            return {'status': 'Success', 'mode': 'Authorization'}

        elif ('service_id' in data) and ('service_secret' in data) and ('service' in data):
            return {'status': 'Success', 'mode': 'Authentication'}

        elif 'refresh_token' in data:
            return {'status': 'Success', 'mode': 'Update tokens'}

        else:
            return {'status': 'Failed', 'message': 'Bad request', 'code': 400}

    def authentication(self, data):
        service = Services.objects.filter(service_id=data['service_id'])
        if not service or BaseView.hash_password(data['service_secret']) != service[0].service_secret:
            return {'status': 'Failed', 'message': 'Invalid credentials', 'code': 400}
        tokens = BaseView.get_tokens(access_token_size, refresh_token_size, access_token_ttl, refresh_token_ttl,
                                         from_service=service[0].service_id, to_service=data['service'], type='Service')
        return {'status': 'Success', 'data': tokens, 'code': 200}


class ServiceAuthView(BaseServiceAuthView):

    def post(self, request):
        data = json.loads(request.body.decode('utf-8'))
        result = self.data_analizer(data)

        if result['status'] != 'Success':
            return result

        mode = result['mode']

        if mode == 'Authorization':
            result = BaseView.token_verification(data['access_token'], 'from_service', 'to_service', 'type')
            if result['status'] != 'Success':
                return result
            return {'status': 'Success', 'data': result['data'], 'code': 200}

        elif mode == 'Authentication':
            result = self.authentication(data)
            return result

        elif mode == 'Update tokens':
            result = BaseServiceAuthView.update_tokens(access_token_size, refresh_token_size, access_token_ttl,
                                                           refresh_token_ttl, data['refresh_token'], 'from_service',
                                                           'to_service', 'type')

            # self.log.info('Обновление токенов пользователя')
            return result
