import time
import json
import requests
from flask import current_app as app
from flask import request
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended.exceptions import *
from flask_restplus import Namespace, Resource
from jwt.exceptions import *
from .auth_controller import access_required

api = Namespace('project', description='Namespace for project service')

_http_headers = {'Content-Type': 'application/json'}

_es_index = 'pc_projects'
_es_type = 'project'
_es_size = 100

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


@api.route('/<string:device_id>')
class DeviceByID(Resource):

    @access_required(access='CREATE_DEVICE DELETE_DEVICE UPDATE_DEVICE SEARCH_DEVICE VIEW_DEVICE')
    @api.doc('get device details by id')
    def get(self, device_id):
        app.logger.info('Get device_details method called')
        rs = requests.session()
        search_url = 'http://{}/{}/{}/{}'.format(app.config['ES_HOST'], _es_index, _es_type, device_id)
        response = rs.get(url=search_url, headers=_http_headers).json()
        if 'found' in response:
            if response['found']:
                data = response['_source']
                data['id'] = response['_id']
                app.logger.info('Get device_details method completed')
                return data, 200
            app.logger.warning('Device not found')
            return {'found': response['found']}, 404
        app.logger.error('Elasticsearch down, response: ' + str(response))
        return response, 500

    @access_required(access='CREATE_DEVICE DELETE_DEVICE UPDATE_DEVICE')
    @api.doc('update device by id')
    def put(self, device_id):
        app.logger.info('Update device_details method called')
        current_user = get_jwt_identity().get('id')
        rs = requests.session()
        post_data = request.get_json()
        search_url = 'http://{}/{}/{}/{}'.format(app.config['ES_HOST'], _es_index, _es_type, device_id)
        response = rs.get(url=search_url, headers=_http_headers).json()
        if 'found' in response:
            if response['found']:
                data = response['_source']
                for key, value in post_data.items():
                    data[key] = value
                data['updated_by'] = current_user
                data['updated_at'] = int(time.time())
                response = rs.put(url=search_url, json=data, headers=_http_headers).json()
                if 'result' in response:
                    app.logger.info('Update device_details method completed')
                    return response['result'], 200
            app.logger.warning('Device not found')
            return {'message': 'not found'}, 404
        app.logger.error('Elasticsearch down, response: ' + str(response))
        return response, 500

    @access_required(access='DELETE_DEVICE')
    @api.doc('delete device by id')
    def delete(self, device_id):
        app.logger.info('Delete device_details method called')
        rs = requests.session()
        search_url = 'http://{}/{}/{}/{}'.format(app.config['ES_HOST'], _es_index, _es_type, device_id)
        response = rs.delete(url=search_url, headers=_http_headers).json()
        print('response: ', response)
        if 'found' in response:
            return response['result'], 200
        app.logger.error('Elasticsearch down, response: ' + str(response))
        return response, 500


@api.route('/')
class CreateDevice(Resource):

    @access_required(access='CREATE_DEVICE DELETE_DEVICE')
    @api.doc('create new device')
    def post(self):
        app.logger.info('Create device method called')
        current_user = get_jwt_identity().get('id')
        rs = requests.session()
        data = request.get_json()
        mandatory_fields = []

        for field in mandatory_fields:
            if field not in data:
                app.logger.warning('required fields are missing')
                return {"message": "required fields are missing"}, 400

        query_json = {'query': {'bool': {'must': [{'term': {'ip_address': data['ip_address']}}]}}}
        query_json['size'] = 1
        search_url = 'http://{}/{}/{}/_search'.format(app.config['ES_HOST'], _es_index, _es_type)
        response = requests.session().post(url=search_url, json=query_json, headers=_http_headers).json()

        if 'hits' in response:
            if len(response['hits']['hits']) > 0:
                return {'message': 'ip_address is already assigned to a device'}, 400

        data['created_by'] = current_user
        data['created_at'] = int(time.time())
        data['updated_by'] = current_user
        data['updated_at'] = int(time.time())
        post_url = 'http://{}/{}/{}'.format(app.config['ES_HOST'], _es_index, _es_type)
        response = rs.post(url=post_url, json=data, headers=_http_headers).json()

        if 'created' in response:
            if response['created']:
                app.logger.info('Create device method completed')
                return response['_id'], 201
        app.logger.error('Elasticsearch down, response: ' + str(response))
        return response, 500


@api.route('/search', defaults={'page': 0})
@api.route('/search/<int:page>')
class SearchDevice(Resource):

    @access_required(access='CREATE_DEVICE DELETE_DEVICE UPDATE_DEVICE SEARCH_DEVICE VIEW_DEVICE')
    @api.doc('search door based on post parameters')
    def post(self, page=0):
        app.logger.info('Search device method called')
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
                device = hit['_source']
                device['id'] = hit['_id']
                data.append(device)
            app.logger.info('Search device method completed')
            return data, 200
        app.logger.error('Elasticsearch down, response: ' + str(response))
        return {'message': 'internal server error'}, 500