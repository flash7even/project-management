from hashlib import md5
from datetime import timedelta
import requests
from functools import wraps
from flask import request, current_app as app
from flask_restplus import Resource, Namespace
from flask_jwt_extended import create_access_token, create_refresh_token, jwt_refresh_token_required, get_jwt_identity, jwt_required, get_raw_jwt, verify_jwt_in_request, get_jwt_claims
from flask_jwt_extended.exceptions import *
from jwt.exceptions import *

api = Namespace('auth', description='auth related services')
_http_headers = {'Content-Type': 'application/json'}
_source = ['username', 'user_role', 'user_access', 'fullname']

_es_role_index = 'pms_user_role_lookup'
_es_role_type = 'role'
_es_index = 'pms_users'
_es_type = 'user'


@api.errorhandler(NoAuthorizationError)
def handle_auth_error(e):
    return {'message': str(e)}, 401


@api.errorhandler(CSRFError)
def handle_auth_error(e):
    return {'message': str(e)}, 401


@api.errorhandler(ExpiredSignatureError)
def handle_expired_error(e):
    return {'message': 'Token has expired'}, 401


@api.errorhandler(InvalidHeaderError)
def handle_invalid_header_error(e):
    return {'message': str(e)}, 422


@api.errorhandler(InvalidTokenError)
def handle_invalid_token_error(e):
    return {'message': str(e)}, 422


@api.errorhandler(JWTDecodeError)
def handle_jwt_decode_error(e):
    return {'message': str(e)}, 422


@api.errorhandler(WrongTokenError)
def handle_wrong_token_error(e):
    return {'message': str(e)}, 422


@api.errorhandler(RevokedTokenError)
def handle_revoked_token_error(e):
    return {'message': 'Token has been revoked'}, 401


@api.errorhandler(FreshTokenRequired)
def handle_fresh_token_required(e):
    return {'message': 'Fresh token required'}, 401


@api.errorhandler(UserLoadError)
def handler_user_load_error(e):
    identity = get_jwt_identity().get('id')
    return {'message': "Error loading the user {}".format(identity)}, 401


@api.errorhandler(UserClaimsVerificationError)
def handle_failed_user_claims_verification(e):
    return {'message': 'User claims verification failed'}, 400


def access_required(access='ALL'):
    def callable(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            verify_jwt_in_request()
            claims = get_jwt_claims()
            if 'ALL' not in access:
                methods = access.split()
                claims_list = claims['methods'].split()
                a_methods = set(methods)
                c_methods = set(claims_list)
                if len(a_methods.intersection(c_methods)) == 0:
                    claim_methods = claims['methods']
                    claim_role = claims['role']
                    return {"message": f'{claim_role} only has access to methods {claim_methods} only!'}, 403
            return fn(*args, **kwargs)
        return wrapper
    return callable


def generate_access_string_from_roles(user_role):
    role_names = user_role.split()
    app.logger.debug(f'Preparing method access rules for roles {role_names}')

    query = {'size': len(role_names), 'query': {'terms': {'role_id': role_names}}}

    search_url = 'http://{}/{}/{}/{}'.format(app.config['ES_HOST'], _es_role_index, _es_role_type, '_search')

    rs = requests.session()

    response = rs.post(url=search_url, json=query).json()
    if 'hits' in response:
        all_method_access = {}
        for hit in response['hits']['hits']:
            method_access = hit['_source'].get('method_access')
            for access in method_access:
                all_method_access[access['access_code']] = access
        return list(all_method_access.values())
    else:
        raise RuntimeError


@api.route('/login')
class Login(Resource):

    def post(self):
        rs = requests.session()
        auth_data = request.get_json()
        app.logger.info("Authorization called")
        if 'username' in auth_data and 'password' in auth_data:
            username = auth_data['username']
            password = md5(auth_data['password'].encode(encoding='utf-8')).hexdigest()
        else:
            app.logger.info("Bad request, authorization failed")
            return "bad request", 400

        auth_url = 'http://{}/{}/{}/_search'.format(app.config['ES_HOST'], _es_index, _es_type)
        auth_query = {
            '_source': _source,
            'query': {'bool': {'must': [{'match': {'username': username}}, {'match': {'password': password}}]}}}
        response = rs.post(url=auth_url, json=auth_query, headers=_http_headers).json()

        if 'hits' in response:
            if response['hits']['total'] == 1:
                data = response['hits']['hits'][0]['_source']
                data['id'] = response['hits']['hits'][0]['_id']

                try:
                    access_list = generate_access_string_from_roles(data.get('user_role'))
                except RuntimeError as err:
                    app.logger.error('Elasticsearch down, response: ' + str(response))
                    return 'Elasticsearch error', 500

                jwt_data = {}
                jwt_data['user_access'] = ' '.join([item['access_code'] for item in access_list])
                data['user_access'] = jwt_data['user_access']
                jwt_data['id'] = data['id']
                jwt_data['username'] = data['username']
                jwt_data['fullname'] = data['fullname']
                jwt_data['user_role'] = data['user_role']
                data['access_token'] = create_access_token(identity=jwt_data)
                data['refresh_token'] = create_refresh_token(identity=jwt_data)
                app.logger.info("login successful")
                return data, 200
            else:
                app.logger.info("Unauthorized")
                return {"message": "unauthorized"}, 401
        app.logger.error('Elasticsearch down, response: ' + str(response))
        return response, 500


@api.route('/refresh')
class Refresh(Resource):

    @jwt_refresh_token_required
    def post(self):
        rs = requests.session()
        app.logger.info("refresh called")
        current_user = get_jwt_identity().get('id')
        auth_url = 'http://{}/{}/{}/{}'.format(app.config['ES_HOST'], _es_index, _es_type, current_user)
        response = rs.get(url=auth_url, headers=_http_headers).json()
        if 'found' in response:
            if response['found']:
                data = response['_source']
                data['id'] = response['_id']
                try:
                    access_list = generate_access_string_from_roles(data.get('user_role'))
                except RuntimeError as err:
                    app.logger.error('Elasticsearch down, response: ' + str(response))
                    return 'Elasticsearch error', 500

                jwt_data = {}
                jwt_data['user_access'] = ' '.join([item['access_code'] for item in access_list])
                data['user_access'] = jwt_data['user_access']
                jwt_data['id'] = data['id']
                jwt_data['username'] = data['username']
                jwt_data['fullname'] = data['fullname']
                jwt_data['user_role'] = data['user_role']
                data['access_token'] = create_access_token(identity=jwt_data)
                data['refresh_token'] = create_refresh_token(identity=jwt_data)
                app.logger.info("refresh successful")
                return data, 200
            else:
                app.logger.info("Unauthorized")
                return {"message": "unauthorized"}, 401
        app.logger.error('Elasticsearch down, response: ' + str(response))
        return response, 500

