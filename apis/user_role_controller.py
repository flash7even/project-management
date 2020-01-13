import json
import time

import requests
from flask import current_app as app
from flask import request
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended.exceptions import *
from flask_restplus import Namespace, Resource
from jwt.exceptions import *

from .auth_controller import access_required

api = Namespace('role', description='Namespace for role service')

_http_headers = {'Content-Type': 'application/json'}

_es_index = 'pms_user_role_lookup'
_es_type = 'role'
_es_access_index = 'pms_method_access_lookup'
_es_access_type = 'access'
_es_size = 100
mandatory_fields = ["role_name", "role_id", "role_level", "method_access"]

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


def convert_data(data):
    app.logger.info('convert_data method called')
    data_js = []
    for d in data:
        must = ({'term': {'access_code': d}})
        access_js = {}
        query_json = {'query': {'bool': {'must': must}}}
        search_url = 'http://{}/{}/{}/_search'.format(app.config['ES_HOST'], _es_access_index, _es_access_type)
        response = requests.session().post(url=search_url, json=query_json, headers=_http_headers).json()
        if 'hits' in response:
            for hit in response['hits']['hits']:
                access_js['access_code'] = d
                access_js['access_name'] = hit['_source']['access_name']
            data_js.append(access_js)
    app.logger.info('convert_data method completed')
    return data_js


@api.route('/<string:role_id>')
class RoleByID(Resource):

    @access_required(access='DELETE_USER CREATE_USER UPDATE_USER SEARCH_USER VIEW_USER')
    @api.doc('get role details by id')
    def get(self, role_id):
        app.logger.info('Get user role service called')
        rs = requests.session()
        search_url = 'http://{}/{}/{}/{}'.format(app.config['ES_HOST'], _es_index, _es_type, role_id)
        response = rs.get(url=search_url, headers=_http_headers).json()
        if 'found' in response:
            if response['found']:
                data = response['_source']
                data['id'] = response['_id']
                app.logger.info('Get user role service completed')
                return data, 200
            app.logger.warning('Role not found')
            return {'found': response['found']}, 404
        app.logger.error('Elasticsearch down, response: ' + str(response))
        return response, 500

    @access_required(access='DELETE_USER CREATE_USER UPDATE_USER')
    @api.doc('update role by id')
    def put(self, role_id):
        app.logger.info('Update user role service called')
        current_user = get_jwt_identity().get('id')
        rs = requests.session()
        post_data = request.get_json()
        search_url = 'http://{}/{}/{}/{}'.format(app.config['ES_HOST'], _es_index, _es_type, role_id)
        response = rs.get(url=search_url, headers=_http_headers).json()
        if 'found' in response:
            if response['found']:
                data = response['_source']
                for key, value in post_data.items():
                    if key == 'method_access':
                        data[key] = convert_data(value)
                    else:
                        data[key] = value
                data['updated_by'] = current_user
                data['updated_at'] = int(time.time())
                response = rs.put(url=search_url, json=data, headers=_http_headers).json()
                if 'result' in response:
                    app.logger.info('Update user role service completed')
                    return response['result'], 200
            app.logger.warning('Role not found')
            return {'message': 'not found'}, 404
        app.logger.error('Elasticsearch down, response: ' + str(response))
        return response, 500

    @access_required(access='DELETE_USER')
    @api.doc('delete role by id')
    def delete(self, role_id):
        app.logger.info('Delete user role service called')
        rs = requests.session()
        search_url = 'http://{}/{}/{}/{}'.format(app.config['ES_HOST'], _es_index, _es_type, role_id)
        response = rs.delete(url=search_url, headers=_http_headers).json()
        if 'found' in response:
            app.logger.info('Delete user role service completed')
            return response['result'], 200
        app.logger.error('Elasticsearch down, response: ' + str(response))
        return response, 500


@api.route('/')
class CreateRole(Resource):

    @access_required(access='DELETE_USER CREATE_USER')
    @api.doc('create new role')
    def post(self):
        app.logger.info('Create user role service called')
        current_user = get_jwt_identity().get('id')
        rs = requests.session()
        data = request.get_json()

        for field in mandatory_fields:
            if field not in data:
                app.logger.warning('required fields are missing')
                return {"message": "required fields are missing"}, 400

        data['created_by'] = current_user
        data['created_at'] = int(time.time())
        data['updated_by'] = current_user
        data['updated_at'] = int(time.time())
        data['method_access'] = convert_data(data['method_access'])
        post_url = 'http://{}/{}/{}'.format(app.config['ES_HOST'], _es_index, _es_type)
        response = rs.post(url=post_url, json=data, headers=_http_headers).json()

        if 'created' in response:
            if response['created']:
                app.logger.info('Create user role service completed')
                return response['_id'], 201
        app.logger.error('Elasticsearch down, response: ' + str(response))
        return response, 500


@api.route('/search', defaults={'page': 0})
@api.route('/search/<int:page>')
class SearchRole(Resource):

    @access_required(access='DELETE_USER CREATE_USER UPDATE_USER SEARCH_USER VIEW_USER')
    @api.doc('search role based on post parameters')
    def post(self, page=0):
        app.logger.info('Search role on post parameter API called')
        param = request.get_json()

        query_json = {'query': {'match_all': {}}}

        must = []

        for fields in param:
            must.append({'match': {fields: param[fields]}})

        if len(must) > 0:
            query_json = {'query': {'bool': {'must': must}}}

        query_json['from'] = page * _es_size
        query_json['size'] = _es_size
        search_url = 'http://{}/{}/{}/_search'.format(app.config['ES_HOST'], _es_index, _es_type)

        response = requests.session().post(url=search_url, json=query_json, headers=_http_headers).json()
        if 'hits' in response:
            data = []
            for hit in response['hits']['hits']:
                user = hit['_source']
                user['id'] = hit['_id']
                data.append(user)
            app.logger.info('Search role on post parameter API completed')
            return data, 200
        app.logger.error('Elasticsearch down, response: ' + str(response))
        return {'message': 'internal server error'}, 500


@api.route('/dtsearch')
class SearchRoleDT(Resource):

    @access_required(access='DELETE_USER CREATE_USER UPDATE_USER SEARCH_USER VIEW_USER')
    @api.doc('search roles based on query parameters')
    def get(self):
        app.logger.info('User role dtsearch service called')
        param = request.args.to_dict()
        for key in param:
            param[key] = param[key].replace('"', '')

        app.logger.debug('query params: ' + str(param))

        pageIndex = 0
        pageSize = _es_size

        if 'pageIndex' in param:
            pageIndex = int(param['pageIndex'])

        if 'pageSize' in param:
            pageSize = int(param['pageSize'])

        should = []

        if 'filter' in param and param['filter']:
            should.append({'match': {'role_name': param['filter']}})
            should.append({'term': {'role_id': param['filter']}})

        query = {'bool': {'should': should}}

        if len(should) == 0:
            query = {'match_all': {}}

        query_json = {'query': query, 'from': pageIndex * pageSize, 'size': pageSize}

        #if 'sortActive' in param:
        #    query_json['sort'] = [{param['sortActive']: {'order': param['sortOrder']}}]

        app.logger.debug('ES Query: ' + str(json.dumps(query_json)))

        search_url = 'http://{}/{}/{}/_search'.format(app.config['ES_HOST'], _es_index, _es_type)
        response = requests.session().post(url=search_url, json=query_json, headers=_http_headers).json()

        if 'hits' in response:
            data = []
            for hit in response['hits']['hits']:
                user = hit['_source']
                user['id'] = hit['_id']
                data.append(user)
            return_data = {
                'role_list': data,
                'count': response['hits']['total']
            }
            app.logger.info('User role dtsearch service completed')
            return return_data, 200
            # return data, 200
        app.logger.error('Elasticsearch down, response: ' + str(response))
        return {'message': 'internal server error'}, 500
