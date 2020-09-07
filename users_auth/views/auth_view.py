import sys

sys.path.append('../../')

from ..models import Users
from baseView import BaseView
import json
from django.conf import settings

access_token_ttl = settings.USERS_ACCESS_TOKEN_TTL
refresh_token_ttl = settings.USERS_REFRESH_TOKEN_TTL
access_token_size = settings.USERS_ACCESS_TOKEN_SIZE
refresh_token_size = settings.USERS_REFRESH_TOKEN_SIZE


class BaseUserAuthView(BaseView):

    def data_analizer(self, data):
        if 'access_token' in data:
            return {'status': 'Success', 'mode': 'Authorization'}

        elif ('login' in data) and ('password' in data):
            return {'status': 'Success', 'mode': 'Authentication'}

        elif 'refresh_token' in data:
            return {'status': 'Success', 'mode': 'Update tokens'}

        else:
            return {'status': 'Failed', 'message': 'Bad request', 'code': 400}

    def authentication(self, data):
        user = Users.objects.filter(login=data['login'])
        if not user or BaseView.hash_password(data['password']) != user[0].password:
            return {'status': 'Failed', 'message': 'Invalid credentials', 'code': 400}
        tokens = BaseView.get_tokens(access_token_size, refresh_token_size, access_token_ttl, refresh_token_ttl,
                                         uuid=user[0].uuid, role=user[0].role, type='User')
        return {'status': 'Success', 'data': tokens, 'code': 200}


class UserAuthView(BaseUserAuthView):

    def post(self, request):
        data = json.loads(request.body.decode('utf-8'))
        result = self.data_analizer(data)

        if result['status'] != 'Success':
            return result

        mode = result['mode']

        if mode == 'Authorization':
            result = BaseView.token_verification(data['access_token'], 'uuid', 'role', 'type')
            if result['status'] != 'Success':
                return result
            return {'status': 'Success', 'data': result['data'], 'code': 200}

        elif mode == 'Authentication':
            result = self.authentication(data)
            return result

        elif mode == 'Update tokens':
            result = BaseUserAuthView.update_tokens(access_token_size, refresh_token_size, access_token_ttl,
                                                        refresh_token_ttl, data['refresh_token'], 'uuid', 'role', 'type')

            return result
