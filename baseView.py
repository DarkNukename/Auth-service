from django.views import View
from django.http import JsonResponse
import datetime
import secrets
import copy
import logging
import redis
import os
import hashlib
import sentry_sdk
import base64

from django.conf import settings

r = redis.Redis() if settings.DEBUG else redis.from_url(os.environ.get("REDIS_URL"))
# r = redis.from_url(os.environ.get("REDIS_URL"))

sentry_sdk.init(
    "https://e20a8a5dee99445f8917e97c3b39b260@o438046.ingest.sentry.io/5401287",
    traces_sample_rate=1.0
)

error_log = logging.getLogger('error_log')


class BaseView(View):

    @staticmethod
    def create_tokens(access_token_ttl, refresh_token_ttl, access_token_size, refresh_token_size):

        access_token = secrets.token_urlsafe(access_token_size)
        refresh_token = secrets.token_urlsafe(refresh_token_size)

        now = datetime.datetime.now()
        access_token_valid_until = (now + access_token_ttl).strftime('%d/%m/%y %H:%M:%S')
        refresh_token_valid_until = (now + refresh_token_ttl).strftime('%d/%m/%y %H:%M:%S')

        tokens = {
            'access_token': access_token,
            'refresh_token': refresh_token,
            'access_token_valid_until': access_token_valid_until,
            'refresh_token_valid_until': refresh_token_valid_until
        }

        return tokens

    @staticmethod
    def token_verification(token, *params):
        
        if token == settings.SERVICE_SECRET:
            return {'status': 'Success', 'data': {'type': 'Service', 'from_service': 'Auth', 'to_service': 'Dancers'}}
        
        data = r.hgetall(token)
        decode_data = {}
        if data:
            for key, value in data.items():
                decode_data[key.decode('UTF-8')] = value.decode('UTF-8')
            return {'status': 'Success', 'data': decode_data}
        else:
            return {'status': 'Failed', 'message': 'Bad token', 'code': 400}

    @staticmethod
    def update_tokens(access_token_size, refresh_token_size, access_token_ttl, refresh_token_ttl, refresh_token,
                      *params):
        result = BaseView.token_verification(refresh_token, *params)

        if result['status'] != 'Success':
            return result

        tokens = BaseView.create_tokens(access_token_ttl, refresh_token_ttl, access_token_size, refresh_token_size)
        r.delete(refresh_token)

        ttl = {'access_token': access_token_ttl, 'refresh_token': refresh_token_ttl}
        for token in ('access_token', 'refresh_token'):
            for key, value in result['data'].items():
                r.hset(tokens[token], key, str(value))
            r.expire(tokens[token], ttl[token])
        result = {'status': 'Success', 'data': tokens, 'code': 200}
        return result

    @staticmethod
    def get_tokens(access_token_size, refresh_token_size, access_token_ttl, refresh_token_ttl, **fields):
        tokens = BaseView.create_tokens(access_token_ttl, refresh_token_ttl, access_token_size, refresh_token_size)
        ttl = {'access_token': access_token_ttl, 'refresh_token': refresh_token_ttl}
        for token in ('access_token', 'refresh_token'):
            for key, value in fields.items():
                print(key, value)
                r.set('key', 'value')
                print(r.get('key'))
                r.hset(tokens[token], key, str(value))
            r.expire(tokens[token], ttl[token])
        return tokens

    def dispatch(self, request, *args, **kwargs):

        try:
            response = super().dispatch(request, *args, **kwargs)
        except Exception as e:
            sentry_sdk.capture_exception(error=e)
            BaseView.error_log(error_log, e, request)
            return JsonResponse({'status': 'Failed', 'message': 'Server error'}, status=500)

        if isinstance(response, (dict, list)):
            status = response.pop('code')
            return JsonResponse(response, safe=False, status=status)
        else:
            return response

    @staticmethod
    def authorization(roles):
        def decorator(func):
            def wrapper(*args, **kwargs):
                request = args[1]
                access_token = request.headers.get('Authorization')
                if access_token:
                    result = BaseView.token_verification(access_token)
                    if result['status'] != 'Success':
                        return result

                    if result['data']['type'] == 'User':
                        if result['data']['role'] in roles:
                            kwargs['client_id'] = str(result['data']['uuid'])
                            kwargs['client'] = 'User'
                            return func(*args, **kwargs)
                        else:
                            return {'status': 'Failed', 'message': 'No access', 'code': 403}
                else:
                    if 'anonymous' in roles:
                        kwargs['client_id'] = 'anonymous'
                        kwargs['client'] = 'anonymous'
                        return func(*args, **kwargs)
                    else:
                        return {'status': 'Failed', 'message': 'No access', 'code': 403}

            return wrapper

        return decorator

    @staticmethod
    def hash_password(password):
        h = hashlib.sha256(password.encode('UTF-8'))
        return h.hexdigest()

    @staticmethod
    def log(logger, request, client, client_id):
        log_message = 'Method: {} - URL: {} - Client: {} - Client ID: {} - Params: {} - Headers: {} -  Data: {}'
        logger.info(log_message.format(request.method, request.build_absolute_uri(), client,
                                       client_id, request.GET, request.headers, request.body.decode('utf-8')
                                       ))

    @staticmethod
    def error_log(logger, error, request):
        log_message = 'ERROR: {} - Method: {} - URL: {} - Params: {} - Headers: {} -  Data: {}'
        logger.info(log_message.format(error, request.method, request.build_absolute_uri(),
                                       request.GET, request.headers, request.body.decode('utf-8')
                                       ))
