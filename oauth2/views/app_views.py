import sys
sys.path.append('../../')

import logging
from baseView import BaseView
from ..models import Application
import json

log = logging.getLogger('app_log')


class ApplicationsView(BaseView):

    @BaseView.authorization(('admin', 'anonymous'))
    def get(self, request, client, client_id):
        params = request.GET
        response = list(Application.objects.filter(**params).values())
        BaseView.log(log, request, client, client_id)
        return {'status': 'Success', 'data': response, 'code': 200}

    @BaseView.authorization(('admin', 'anonymous'))
    def post(self, request, client, client_id):
        # TODO отправка данных на сервис танцоров
        data = json.loads(request.body.decode('utf-8'))
        response = Application.objects.create(**data).pk
        BaseView.log(log, request, client, client_id)
        return {'status': 'Success', 'data': response, 'code': 200}

class ApplicationView(BaseView):

    @BaseView.authorization(('admin', 'anonymous'))
    def get(self, request, uuid, client, client_id):
        response = list(Application.objects.filter(pk=uuid).values())
        if not response:
            return {'status': 'Failed', 'message': 'Object does not exist', 'code': 404}
        BaseView.log(log, request, client, client_id)
        return {'status': 'Success', 'data': response, 'code': 200}

    @BaseView.authorization(('admin', 'anonymous'))
    def patch(self, request, uuid, client, client_id):
        data = json.loads(request.body.decode('utf-8'))
        Application.objects.filter(pk=uuid).update(**data)
        response = list(Application.objects.filter(pk=uuid).values())
        BaseView.log(log, request, client, client_id)
        return {'status': 'Success', 'data': response, 'code': 200}

    @BaseView.authorization(('admin', 'anonymous'))
    def delete(self, request, uuid, client, client_id):
        # TODO отправлка данных на сервис танцоров
        entry = Application.objects.filter(pk=uuid)
        entry.delete()
        BaseView.log(log, request, client, client_id)
        return {'status': 'Success', 'code': 200}