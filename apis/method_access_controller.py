import requests
from flask import current_app as app
from flask import request
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended.exceptions import *
from flask_restplus import Namespace, Resource
from jwt.exceptions import *

from .auth_controller import access_required

api = Namespace('access', description='Namespace for method access service')

_http_headers = {'Content-Type': 'application/json'}

_es_index = 'tardy_method_access_lookup'
_es_type = 'access'
_es_size = 100
mandatory_fields = ["access_code", "access_name", "access_group"]

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


@api.route('/<string:access_id>')
class AccessMethod(Resource):

    @access_required(access='DELETE_USER CREATE_USER UPDATE_USER SEARCH_USER VIEW_USER')
    @api.doc('get method_access details by id')
    def get(self, access_id):
        app.logger.info('Get access API called, id: ' + str(access_id))
        rs = requests.session()
        search_url = 'http://{}/{}/{}/{}'.format(app.config['ES_HOST'], _es_index, _es_type, access_id)
        app.logger.debug('Elasticsearch query : ' + str(search_url))
        response = rs.get(url=search_url, headers=_http_headers).json()
        app.logger.debug('Elasticsearch response :' + str(response))
        if 'found' in response:
            if response['found']:
                data = response['_source']
                data['id'] = response['_id']
                app.logger.info('Get access API completed')
                return data, 200
            app.logger.warning('Access not found')
            return {'found': response['found']}, 404
        app.logger.error('Elasticsearch down')
        return response, 500

    @access_required(access='DELETE_USER CREATE_USER UPDATE_USER')
    @api.doc('update method_access by id')
    def put(self, access_id):
        app.logger.info('Update access API called, id: ' + str(access_id))
        rs = requests.session()
        post_data = request.get_json()
        search_url = 'http://{}/{}/{}/{}'.format(app.config['ES_HOST'], _es_index, _es_type, access_id)
        app.logger.debug('Elasticsearch query : ' + str(search_url))
        response = rs.get(url=search_url, headers=_http_headers).json()
        app.logger.debug('Elasticsearch response :' + str(response))
        if 'found' in response:
            if response['found']:
                data = response['_source']
                for key, value in post_data.items():
                    data[key] = value
                response = rs.put(url=search_url, json=data, headers=_http_headers).json()
                if 'result' in response:
                    app.logger.info('Update access API completed')
                    return response['result'], 200
            app.logger.warning('Access not found')
            return {'message': 'not found'}, 404
        app.logger.error('Elasticsearch down')
        return response, 500

    @access_required(access='DELETE_USER')
    @api.doc('delete method_access by id')
    def delete(self, access_id):
        app.logger.info('Delete access API called, id: ' + str(access_id))
        rs = requests.session()
        search_url = 'http://{}/{}/{}/{}'.format(app.config['ES_HOST'], _es_index, _es_type, access_id)
        response = rs.delete(url=search_url, headers=_http_headers).json()
        if 'found' in response:
            app.logger.info('Delete access API completed')
            return response['result'], 200
        app.logger.error('Elasticsearch down')
        return response, 500


@api.route('/')
class CreateAccess(Resource):

    @access_required(access='DELETE_USER CREATE_USER')
    @api.doc('create new access')
    def post(self):
        app.logger.info('Create access API called')
        rs = requests.session()
        data = request.get_json()

        for field in mandatory_fields:
            if field not in data:
                app.logger.warning('required fields are missing')
                return {"message": "required fields are missing"}, 400

        post_url = 'http://{}/{}/{}'.format(app.config['ES_HOST'], _es_index, _es_type)
        app.logger.debug('Elasticsearch url : ' + str(post_url))
        response = rs.post(url=post_url, json=data, headers=_http_headers).json()

        if 'created' in response:
            if response['created']:
                app.logger.info('Create access API completed')
                return response['_id'], 201
        app.logger.error('Elasticsearch down')
        return response, 500


@api.route('/search', defaults={'page': 0})
@api.route('/search/<int:page>')
class SearchAccess(Resource):

    @access_required(access='DELETE_USER CREATE_USER UPDATE_USER SEARCH_USER VIEW_USER')
    @api.doc('search access based on post parameters')
    def post(self, page=0):
        app.logger.info('Search access API called')
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
        app.logger.debug('Elasticsearch query : ' + str(query_json))
        response = requests.session().post(url=search_url, json=query_json, headers=_http_headers).json()
        if 'hits' in response:
            data = []
            for hit in response['hits']['hits']:
                user = hit['_source']
                user['id'] = hit['_id']
                data.append(user)
            app.logger.info('Search access API completed')
            return data, 200
        app.logger.error('Elasticsearch down')
        return {'message': 'internal server error'}, 500
