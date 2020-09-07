from django.views import View
import sys
sys.path.append('../../')

import logging
from baseView import BaseView
from ..models import Users
import json
import re


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

    @BaseView.authorization(('admin', 'anonymous'))
    def post(self, request, client, client_id):
        # TODO отправка данных на сервис танцоров
        data = json.loads(request.body.decode('utf-8'))
        result = BaseAccontsView.user_validator(data)
        if result['status'] != 'Success':
            return result

        data['password'] = BaseView.hash_password(data['password'])
        response = Users.objects.create(**data).pk
        BaseView.log(user_auth_log, request, client, client_id)
        return {'status': 'Success', 'data': response, 'code': 200}

class AccountView(BaseView):

    @BaseView.authorization(('admin', 'anonymous'))
    def get(self, request, uuid, client, client_id):
        response = list(Users.objects.filter(pk=uuid).values())
        if not response:
            return {'status': 'Failed', 'message': 'Object does not exist', 'code': 404}
        BaseView.log(user_auth_log, request, client, client_id)
        return {'status': 'Success', 'data': response, 'code': 200}

    @BaseView.authorization(('admin', 'anonymous'))
    def patch(self, request, uuid, client, client_id):
        data = json.loads(request.body.decode('utf-8'))
        Users.objects.filter(pk=uuid).update(**data)
        response = list(Users.objects.filter(pk=uuid).values())
        BaseView.log(user_auth_log, request, client, client_id)
        return {'status': 'Success', 'data': response, 'code': 200}

    @BaseView.authorization(('admin', 'anonymous'))
    def delete(self, request, uuid, client, client_id):
        # TODO отправлка данных на сервис танцоров
        entry = Users.objects.filter(pk=uuid)
        entry.delete()
        BaseView.log(user_auth_log, request, client, client_id)
        return {'status': 'Success', 'code': 200}

class ChangePasswordView(BaseView):

    def post(self, request):
        pass

