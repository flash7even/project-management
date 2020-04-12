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
from core.plibrary import find_document_id

api = Namespace('material', description='Namespace for material service')

_http_headers = {'Content-Type': 'application/json'}

_es_index = 'pms_materials'
_es_type = '_doc'
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


@api.route('/<string:material_id>')
class MaterialByID(Resource):

    #@access_required(access='CREATE_MATERIAL DELETE_MATERIAL UPDATE_MATERIAL SEARCH_MATERIAL VIEW_MATERIAL')
    @api.doc('get material details by id')
    def get(self, material_id):
        app.logger.info('Get material_details api called')
        rs = requests.session()
        search_url = 'http://{}/{}/{}/{}'.format(app.config['ES_HOST'], _es_index, _es_type, material_id)
        response = rs.get(url=search_url, headers=_http_headers).json()
        if 'found' in response:
            if response['found']:
                data = response['_source']
                data['id'] = response['_id']
                app.logger.info('Get material_details api completed')
                return data, 200
            app.logger.warning('Material not found')
            return {'found': response['found']}, 404
        app.logger.error('Elasticsearch down, response: ' + str(response))
        return response, 500

    #@access_required(access='CREATE_MATERIAL DELETE_MATERIAL UPDATE_MATERIAL')
    @api.doc('update material by id')
    def put(self, material_id):
        app.logger.info('Update material_details api called')
        #current_user = get_jwt_identity().get('id')
        rs = requests.session()
        post_data = request.get_json()
        search_url = 'http://{}/{}/{}/{}'.format(app.config['ES_HOST'], _es_index, _es_type, material_id)
        response = rs.get(url=search_url, headers=_http_headers).json()
        if 'found' in response:
            if response['found']:
                data = response['_source']
                for key in post_data:
                    if post_data[key]:
                     data[key] = post_data[key]
                #data['updated_by'] = current_user
                data['updated_at'] = int(time.time())
                response = rs.put(url=search_url, json=data, headers=_http_headers).json()
                if 'result' in response:
                    app.logger.info('Update material_details api completed')
                    return response['result'], 200
            app.logger.warning('Material not found')
            return {'message': 'not found'}, 404
        app.logger.error('Elasticsearch down, response: ' + str(response))
        return response, 500

    #@access_required(access='DELETE_MATERIAL')
    @api.doc('delete material by id')
    def delete(self, material_id):
        app.logger.info('Delete material_details api called')
        rs = requests.session()
        search_url = 'http://{}/{}/{}/{}'.format(app.config['ES_HOST'], _es_index, _es_type, material_id)
        response = rs.delete(url=search_url, headers=_http_headers).json()
        print('response: ', response)
        if 'result' in response and response['result'] == 'deleted':
            return response['result'], 200
        app.logger.error('Elasticsearch down, response: ' + str(response))
        return response, 500


@api.route('/')
class CreateMaterial(Resource):

    #@access_required(access='CREATE_MATERIAL DELETE_MATERIAL')
    @api.doc('create new material')
    def post(self):
        app.logger.info('Create material api called')
        #current_user = get_jwt_identity().get('id')
        rs = requests.session()
        data = request.get_json()
        data['created_at'] = int(time.time())
        data['updated_at'] = int(time.time())

        data['material_id'] = find_document_id(data['project_name'], 8, 6)

        post_url = 'http://{}/{}/{}'.format(app.config['ES_HOST'], _es_index, _es_type)
        response = rs.post(url=post_url, json=data, headers=_http_headers).json()
        app.logger.debug('ES Response: ' + str(response))

        if 'result' in response and response['result'] == 'created':
            app.logger.info('Create material api completed')
            return response['_id'], 201
        app.logger.error('Elasticsearch down, response: ' + str(response))
        return response, 500


@api.route('/search', defaults={'page': 0})
@api.route('/search/<int:page>')
class SearchMaterial(Resource):

    #@access_required(access='CREATE_MATERIAL DELETE_MATERIAL UPDATE_MATERIAL SEARCH_MATERIAL VIEW_MATERIAL')
    @api.doc('search door based on post parameters')
    def post(self, page=0):
        app.logger.info('Search material api called')
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
            material_list = []
            for hit in response['hits']['hits']:
                material = hit['_source']
                material['id'] = hit['_id']
                material_list.append(material)
            app.logger.info('Search material api completed')
            return material_list, 200
        app.logger.error('Elasticsearch down, response: ' + str(response))
        return {'message': 'internal server error'}, 500

