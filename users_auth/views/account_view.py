from django.views import View
import sys
sys.path.append('../../')

import logging
from baseView import BaseView
from ..models import Users
import json
import re
import requests
from django.conf import settings

LOGGING_MIN_LENGTH = 5
LOGGING_MAX_LENGTH = 25
PASSWORD_MIN_LENGTH = 8
PASSWORD_MAX_LENGTH = 25

user_auth_log = logging.getLogger('account_log')


class BaseAccontsView(BaseView):

    @staticmethod
    def user_validator(data):
        logging_re = re.compile(r'[^a-zA-Z0-9.]')

        errors = []

        if not 'login' in data or not 'password' in data:
            return {'status': 'Failed', 'message': 'Bad request', 'code': 400}

        if len(data['login']) < LOGGING_MIN_LENGTH or len(data['login']) > LOGGING_MAX_LENGTH:
            errors.append({'login': 'login length must be from {} to {} symbols'.format(
                LOGGING_MIN_LENGTH, LOGGING_MAX_LENGTH)})

        if len(data['password']) < PASSWORD_MIN_LENGTH or len(data['password']) > PASSWORD_MAX_LENGTH:
            errors.append({'password': 'password length must be from {} to {} symbols'.format(
                PASSWORD_MIN_LENGTH, PASSWORD_MAX_LENGTH)})

        logging_valid = logging_re.search(data['login'])
        if bool(logging_valid):
            errors.append({'logging': 'unacceptable symbols'})

        user = Users.objects.filter(login=data['login'])
        if user:
            errors.append({'login': 'login is already use'})

        if errors:
            return {'status': 'Failed', 'data': errors, 'code': 400}
        else:
            return {'status': 'Success'}


class AccountsView(BaseAccontsView):

    @BaseView.authorization(('admin', 'sportsman'))
    def get(self, request, client, client_id):
        params = request.GET
        response = list(Users.objects.filter(**params).values())
        BaseView.log(user_auth_log, request, client, client_id)
        return {'status': 'Success', 'data': response, 'code': 200}

    @BaseView.authorization(('admin','anonymous'))
    def post(self, request, client, client_id):
        data = json.loads(request.body.decode('utf-8'))
        
        account_data = {}
        account_data['login'] = data.pop('login')
        account_data['password'] = data.pop('password')
        data.pop('role', None)

        result = BaseAccontsView.user_validator(account_data)
        if result['status'] != 'Success':
            return result
        
        response = requests.post(settings.DANCERS_SERVICE_BASE_URL + 'dancers/sportsmans/',
                                headers={'Authorization': settings.SERVICE_SECRET,
                                         'From': settings.SERVICE_ID,
                                         'To': 'Dancers'},
                                json=data)
        
        if response.status_code != 200:
            return {'status': 'Failed', 'message': 'Service Error', 'code': 500}
        
        print(response.json())
        account_data['uuid'] = response.json()['data']
        account_data['password'] = BaseView.hash_password(account_data['password'])
        response = Users.objects.create(**account_data).pk
        BaseView.log(user_auth_log, request, client, client_id)
        return {'status': 'Success', 'data': response, 'code': 200}

class AccountView(BaseView):

    @BaseView.authorization(('admin', 'sportsman'))
    def get(self, request, uuid, client, client_id):
        response = list(Users.objects.filter(pk=uuid).values())
        if not response:
            return {'status': 'Failed', 'message': 'Object does not exist', 'code': 404}
        BaseView.log(user_auth_log, request, client, client_id)
        return {'status': 'Success', 'data': response, 'code': 200}

    @BaseView.authorization(('admin', 'sportsman'))
    def patch(self, request, uuid, client, client_id):
        data = json.loads(request.body.decode('utf-8'))
        Users.objects.filter(pk=uuid).update(**data)
        response = list(Users.objects.filter(pk=uuid).values())
        BaseView.log(user_auth_log, request, client, client_id)
        return {'status': 'Success', 'data': response, 'code': 200}

    @BaseView.authorization(('admin', 'sportsman', 'anonymous'))
    def delete(self, request, uuid, client, client_id):

        response = requests.delete(settings.DANCERS_SERVICE_BASE_URL + 'dancers/sportsman/{}/'.format(uuid),
                                headers={'Authorization': settings.SERVICE_SECRET,
                                         'From': settings.SERVICE_ID,
                                         'To': 'Dancers'},
            )
        print(response.status_code)
        if response.status_code != 200:         
            return {'status': 'Failed', 'message': 'Service Error', 'code': 500}

        entry = Users.objects.filter(pk=uuid)
        entry.delete()
        BaseView.log(user_auth_log, request, client, client_id)
        return {'status': 'Success', 'code': 200}

class ChangePasswordView(BaseView):

    def post(self, request):
        pass

