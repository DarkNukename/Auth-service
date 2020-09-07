import sys
sys.path.append('../../')

import logging
from baseView import BaseView
from ..models import Services
import json

service_log = logging.getLogger('service_log')


class ServicesView(BaseView):

    @BaseView.authorization(('admin', 'anonymous'))
    def get(self, request, client, client_id):
        params = request.GET
        response = list(Services.objects.filter(**params).values())
        BaseView.log(service_log, request, client, client_id)
        return {'status': 'Success', 'data': response, 'code': 200}

    @BaseView.authorization(('admin', 'anonymous'))
    def post(self, request, client, client_id):
        # TODO отправка данных на сервис танцоров
        data = json.loads(request.body.decode('utf-8'))
        data['service_secret'] = BaseView.hash_password(data['service_secret'])
        response = Services.objects.create(**data).pk
        BaseView.log(service_log, request, client, client_id)
        return {'status': 'Success', 'data': response, 'code': 200}

class ServiceView(BaseView):

    @BaseView.authorization(('admin', 'anonymous'))
    def get(self, request, uuid, client, client_id):
        response = list(Services.objects.filter(pk=uuid).values())
        if not response:
            return {'status': 'Failed', 'message': 'Object does not exist', 'code': 404}
        BaseView.log(service_log, request, client, client_id)
        return {'status': 'Success', 'data': response, 'code': 200}

    @BaseView.authorization(('admin', 'anonymous'))
    def patch(self, request, uuid, client, client_id):
        data = json.loads(request.body.decode('utf-8'))
        Services.objects.filter(pk=uuid).update(**data)
        response = list(Services.objects.filter(pk=uuid).values())
        BaseView.log(service_log, request, client, client_id)
        return {'status': 'Success', 'data': response, 'code': 200}

    @BaseView.authorization(('admin', 'anonymous'))
    def delete(self, request, uuid, client, client_id):
        # TODO отправлка данных на сервис танцоров
        entry = Services.objects.filter(pk=uuid)
        entry.delete()
        BaseView.log(service_log, request, client, client_id)
        return {'status': 'Success', 'code': 200}


