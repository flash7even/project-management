import base64
import json
import random
import time
from datetime import timedelta
from hashlib import md5
from random import random
from PIL import Image

import requests
from flask import request, current_app as app
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended.exceptions import *
from flask_restplus import Namespace, Resource
from jwt.exceptions import *

from .auth_controller import access_required

api = Namespace('user', description='user related services')

_local_recognize_url_endpoint = "/recognize/v2"

_http_headers = {'Content-Type': 'application/json'}
_es_index = 'tardy_users'
_es_type = 'user'
_es_role_index = 'tardy_user_role_lookup'
_es_role_type = 'role'
_es_index_device = 'tardy_devices'
_es_type_device = 'device'
_es_index_device_door = 'tardy_door_device_control'
_es_type_device_door = 'control'
_es_index_user_door = 'tardy_user_door_access'
_es_type_user_door = 'access'
_es_index_access_log = 'tardy_access_control_log'
_es_type_access_log = 'log'
_es_index_booth = 'tardy_booths'
_es_type_booth = 'booth'
_es_door_index = 'tardy_doors'
_es_door_type = 'door'

_es_size = 100
keywords = ["internal_id", "status"]
match_mandatory_fields = ['image_data', 'threshold', 'ip_address']
_es_src_filter = ["fullname"]

device_type_entry_door = 'entry_door'
device_type_exit_door = 'exit_door'
device_type_indoor = 'indoor'
device_type_outdoor = 'outdoor'

entry = 'entry'
exit = 'exit'
active = "active"
delete = "delete"
pending = 'pending'
unknown = 'unknown'
found = 'found'
unauthorized = 'unauthorized'
authorized = 'authorized'
user_hash_fields = ['fullname', 'phone']
image_rect_factor = 0.05


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


def get_user_details(user_id):
    app.logger.info('get_user_details method called')
    rs = requests.session()
    search_url = 'http://{}/{}/{}/{}'.format(app.config['ES_HOST'], _es_index, _es_type, user_id)
    response = rs.get(url=search_url, headers=_http_headers).json()
    if 'found' in response:
        if response['found']:
            app.logger.info('get_user_details method completed')
            return response['_source']
    else:
        app.logger.error('Elasticsearch down, response: ' + str(response))
        return response

    app.logger.info('No user found')
    return {}


@api.route('/<string:user_id>')
class User(Resource):

    @access_required(access='VIEW_USER CREATE_USER DELETE_USER UPDATE_USER SEARCH_USER')
    @api.doc('get user by id')
    def get(self, user_id):
        app.logger.info('Get user info api called')
        rs = requests.session()
        try:
            search_url = 'http://{}/{}/{}/_search'.format(app.config['ES_HOST'], _es_index, _es_type)
            search_query = {'query': {'bool': {'must': [{'term': {'_id': user_id}}]}}}
            response = rs.post(url=search_url, json=search_query, headers=_http_headers).json()

            if 'hits' not in response:
                return {'message': 'internal server error'}, 500
            if response['hits']['total'] > 0:
                es_data = response['hits']['hits'][0]['_source']
                es_data['id'] = response['hits']['hits'][0]['_id']
                app.logger.info('Get user info api completed')
                return es_data, 200
            else:
                app.logger.warning('no user found')
                return {"message": 'no user found'}, 200
            app.logger.error('Elasticsearch down, response: ' + str(response))
            return {'message': str(response)}, 500

        except Exception as e:
            app.logger.error('Elasticsearch down, response: ' + str(response))
            return {'message': str(e)}, 500

    @access_required(access='DELETE_USER CREATE_USER UPDATE_USER')
    @api.doc('update user by id')
    def put(self, user_id):
        app.logger.info("User update service called")
        ignore_fields = ['username', 'password', 'user_access']

        app.logger.info('Update user API called, id: ' + str(user_id))

        rs = requests.session()
        user_data = request.get_json()

        search_url = 'http://{}/{}/{}/{}'.format(app.config['ES_HOST'], _es_index, _es_type, user_id)
        response = rs.get(url=search_url, headers=_http_headers).json()
        if 'found' in response:
            if response['found']:
                user = response['_source']
                for key, value in user.items():
                    if key not in ignore_fields and key in user_data and user_data[key] != value:
                        user[key] = user_data[key]
                response = rs.put(url=search_url, json=user, headers=_http_headers).json()
                if 'result' in response:
                    app.logger.info("User update service completed")
                    return response['result'], 200
            return 'not found', 404
        app.logger.error('Elasticsearch down, response: ' + str(response))
        return response, 500

    @access_required(access='DELETE_USER')
    @api.doc('delete user by id')
    def delete(self, user_id):
        app.logger.info("User delete service called")
        rs = requests.session()
        search_url = 'http://{}/{}/{}/{}'.format(app.config['ES_HOST'], _es_index, _es_type, user_id)
        response = rs.delete(url=search_url, headers=_http_headers).json()
        if 'found' in response:
            app.logger.info("User delete service completed")
            return response['result'], 200
        app.logger.error('Elasticsearch down, response: ' + str(response))
        return response, 500


@api.route('/')
class CreateUser(Resource):

    @staticmethod
    def __validate_json(json_data):
        mandatory_fields = ['username', 'password', 'fullname', 'user_role', 'phone']
        for key, value in json_data.items():
            if key in mandatory_fields and not value:
                raise KeyError('Mandatory field missing')
        return json_data

    @access_required(access='DELETE_USER CREATE_USER')
    @api.doc('create new user')
    def post(self):
        app.logger.info('Create user API called')
        rs = requests.session()
        data = request.get_json()

        try:
            user_data = self.__validate_json(data)
            user_data['password'] = md5(user_data['password'].encode(encoding='utf-8')).hexdigest()
        except (IOError, KeyError):
            app.logger.warning('Bad request')
            return 'bad request', 400

        search_url = 'http://{}/{}/{}/_search'.format(app.config['ES_HOST'], _es_index, _es_type)
        query_params = {'query': {'bool': {'must': [{'match': {'username': data['username']}}]}}}
        response = rs.post(url=search_url, json=query_params, headers=_http_headers).json()

        if 'hits' in response:
            if response['hits']['total'] >= 1:
                app.logger.warning('Username already exists')
                return 'username already exists', 200
        post_url = 'http://{}/{}/{}'.format(app.config['ES_HOST'], _es_index, _es_type)
        response = rs.post(url=post_url, json=user_data, headers=_http_headers).json()

        if 'result' in response:
            if response['result'] == 'created' or response['result'] == 'updated':
                app.logger.info("Created user service called")
                return response['_id'], 201
        app.logger.error('Elasticsearch down, response: ' + str(response))
        return response, 500


@api.route('/search', defaults={'page': 0})
@api.route('/search/<int:page>')
class SearchUser(Resource):

    @access_required(access='DELETE_USER CREATE_USER UPDATE_USER SEARCH_USER VIEW_USER')
    @api.doc('search users based on post parameters')
    def post(self, page=0):
        rs = requests.session()
        app.logger.info("User search service called")
        param = request.get_json()

        query_json = {'query': {'bool': {'must': []}}}

        for k in param:
            if k in keywords:
                query_json['query']['bool']['must'].append({'term': {k: param[k]}})
            else:
                query_json['query']['bool']['must'].append({'match': {k: param[k]}})

        query_json['from'] = page * _es_size
        query_json['size'] = _es_size
        search_url = 'http://{}/{}/{}/_search'.format(app.config['ES_HOST'], _es_index, _es_type)

        response = rs.post(url=search_url, json=query_json, headers=_http_headers).json()
        if 'hits' in response:
            data = []
            for rec in response['hits']['hits']:
                tdata = rec['_source']
                tdata['id'] = rec['_id']
                data.append(tdata)
            app.logger.info("User search service completed")
            return data, 200
        app.logger.error('Elasticsearch down, response: ' + str(response))
        return {'message': 'internal server error'}, 500
