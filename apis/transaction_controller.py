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

api = Namespace('transaction', description='Namespace for transaction service')

_http_headers = {'Content-Type': 'application/json'}

_es_index = 'pms_transactions'
_es_type = 'transaction'
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


@api.route('/<string:transaction_id>')
class TransactionByID(Resource):

    #@access_required(access='CREATE_TRANSACTION DELETE_TRANSACTION UPDATE_TRANSACTION SEARCH_TRANSACTION VIEW_TRANSACTION')
    @jwt_required
    @api.doc('get transaction details by id')
    def get(self, transaction_id):
        app.logger.info('Get transaction_details method called')
        rs = requests.session()
        search_url = 'http://{}/{}/{}/{}'.format(app.config['ES_HOST'], _es_index, _es_type, transaction_id)
        response = rs.get(url=search_url, headers=_http_headers).json()
        if 'found' in response:
            if response['found']:
                data = response['_source']
                data['id'] = response['_id']
                app.logger.info('Get transaction_details method completed')
                return data, 200
            app.logger.warning('Transaction not found')
            return {'found': response['found']}, 404
        app.logger.error('Elasticsearch down, response: ' + str(response))
        return response, 500

    #@access_required(access='CREATE_TRANSACTION DELETE_TRANSACTION UPDATE_TRANSACTION')
    @jwt_required
    @api.doc('update transaction by id')
    def put(self, transaction_id):
        app.logger.info('Update transaction_details method called')
        current_user = get_jwt_identity().get('id')
        rs = requests.session()
        post_data = request.get_json()
        search_url = 'http://{}/{}/{}/{}'.format(app.config['ES_HOST'], _es_index, _es_type, transaction_id)
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
                    app.logger.info('Update transaction_details method completed')
                    return response['result'], 200
            app.logger.warning('Transaction not found')
            return {'message': 'not found'}, 404
        app.logger.error('Elasticsearch down, response: ' + str(response))
        return response, 500

    #@access_required(access='DELETE_TRANSACTION')
    @api.doc('delete transaction by id')
    @jwt_required
    def delete(self, transaction_id):
        app.logger.info('Delete transaction_details method called')
        rs = requests.session()
        search_url = 'http://{}/{}/{}/{}'.format(app.config['ES_HOST'], _es_index, _es_type, transaction_id)
        response = rs.delete(url=search_url, headers=_http_headers).json()
        print('response: ', response)
        if 'found' in response:
            return response['result'], 200
        app.logger.error('Elasticsearch down, response: ' + str(response))
        return response, 500


@api.route('/')
class CreateTransaction(Resource):

    #@access_required(access='CREATE_TRANSACTION DELETE_TRANSACTION')
    @api.doc('create new transaction')
    @jwt_required
    def post(self):
        app.logger.info('Create transaction method called')
        current_user = get_jwt_identity().get('id')
        rs = requests.session()
        data = request.get_json()

        data['created_by'] = current_user
        data['created_at'] = int(time.time())
        data['updated_by'] = current_user
        data['updated_at'] = int(time.time())
        post_url = 'http://{}/{}/{}'.format(app.config['ES_HOST'], _es_index, _es_type)
        response = rs.post(url=post_url, json=data, headers=_http_headers).json()

        if 'created' in response:
            if response['created']:
                app.logger.info('Create transaction method completed')
                return response['_id'], 201
        app.logger.error('Elasticsearch down, response: ' + str(response))
        return response, 500


@api.route('/search', defaults={'page': 0})
@api.route('/search/<int:page>')
class SearchTransaction(Resource):

    #@access_required(access='CREATE_TRANSACTION DELETE_TRANSACTION UPDATE_TRANSACTION SEARCH_TRANSACTION VIEW_TRANSACTION')
    @api.doc('search door based on post parameters')
    @jwt_required
    def post(self, page=0):
        app.logger.info('Search transaction method called')
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
            transaction_list = []
            for hit in response['hits']['hits']:
                transaction = hit['_source']
                transaction['id'] = hit['_id']
                transaction_list.append(transaction)
            app.logger.info('Search transaction method completed')
            return transaction_list, 200
        app.logger.error('Elasticsearch down, response: ' + str(response))
        return {'message': 'internal server error'}, 500