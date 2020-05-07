import time
import json
import datetime
import requests
from flask import current_app as app
from flask import request
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended.exceptions import *
from flask_restplus import Namespace, Resource
from jwt.exceptions import *
from .auth_controller import access_required
from core.transaction_services import find_transaction_stat
from core.bill_services import find_bill_stat

api = Namespace('payment_method', description='Namespace for payment_method service')

_http_headers = {'Content-Type': 'application/json'}

_es_index = 'pms_payment_method'
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


@api.route('/<string:payment_method_id>')
class PaymentMethodByID(Resource):

    #@access_required(access='CREATE_PAYMENT_METHOD DELETE_PAYMENT_METHOD UPDATE_PAYMENT_METHOD SEARCH_PAYMENT_METHOD VIEW_PAYMENT_METHOD')
    @api.doc('get payment_method details by id')
    def get(self, payment_method_id):
        app.logger.info('Get payment_method_details method called')
        rs = requests.session()
        search_url = 'http://{}/{}/{}/{}'.format(app.config['ES_HOST'], _es_index, _es_type, payment_method_id)
        response = rs.get(url=search_url, headers=_http_headers).json()
        if 'found' in response:
            if response['found']:
                data = response['_source']
                data['id'] = response['_id']
                app.logger.info('Get payment_method_details method completed')
                return data, 200
            app.logger.warning('PaymentMethod not found')
            return {'found': response['found']}, 404
        app.logger.error('Elasticsearch down, response: ' + str(response))
        return response, 500

    #@access_required(access='CREATE_PAYMENT_METHOD DELETE_PAYMENT_METHOD UPDATE_PAYMENT_METHOD')
    @api.doc('update payment_method by id')
    def put(self, payment_method_id):
        app.logger.info('Update payment_method_details method called')
        #current_user = get_jwt_identity().get('id')
        rs = requests.session()
        post_data = request.get_json()
        search_url = 'http://{}/{}/{}/{}'.format(app.config['ES_HOST'], _es_index, _es_type, payment_method_id)
        response = rs.get(url=search_url, headers=_http_headers).json()
        if 'found' in response:
            if response['found']:
                data = response['_source']
                for key in post_data:
                    if post_data[key]:
                     data[key] = post_data[key]
                #data['updated_by'] = current_user
                data['updated_at'] = str(datetime.date.today())
                response = rs.put(url=search_url, json=data, headers=_http_headers).json()
                if 'result' in response:
                    app.logger.info('Update payment_method_details method completed')
                    return response['result'], 200
            app.logger.warning('Payment Method not found')
            return {'message': 'not found'}, 404
        app.logger.error('Elasticsearch down, response: ' + str(response))
        return response, 500

    #@access_required(access='DELETE_PAYMENT_METHOD')
    @api.doc('delete payment_method by id')
    def delete(self, payment_method_id):
        app.logger.info('Delete payment_method_details method called')
        rs = requests.session()
        search_url = 'http://{}/{}/{}/{}'.format(app.config['ES_HOST'], _es_index, _es_type, payment_method_id)
        response = rs.delete(url=search_url, headers=_http_headers).json()
        print('response: ', response)
        if 'result' in response and response['result'] == 'deleted':
            return response['result'], 200
        app.logger.error('Elasticsearch down, response: ' + str(response))
        return response, 500


@api.route('/')
class CreatePaymentMethod(Resource):

    #@access_required(access='CREATE_PAYMENT_METHOD DELETE_PAYMENT_METHOD')
    @api.doc('create new payment_method')
    def post(self):
        app.logger.info('Create payment_method method called')
        #current_user = get_jwt_identity().get('id')
        rs = requests.session()
        data = request.get_json()
        data['created_at'] = str(datetime.date.today())
        data['updated_at'] = str(datetime.date.today())

        post_url = 'http://{}/{}/{}'.format(app.config['ES_HOST'], _es_index, _es_type)
        response = rs.post(url=post_url, json=data, headers=_http_headers).json()
        app.logger.debug('ES Response: ' + str(response))

        if 'result' in response and response['result'] == 'created':
            app.logger.info('Create payment_method method completed')
            return response['_id'], 201
        app.logger.error('Elasticsearch down, response: ' + str(response))
        return response, 500


@api.route('/search', defaults={'page': 0})
@api.route('/search/<int:page>')
class SearchPaymentMethod(Resource):

    #@access_required(access='CREATE_PAYMENT_METHOD DELETE_PAYMENT_METHOD UPDATE_PAYMENT_METHOD SEARCH_PAYMENT_METHOD VIEW_PAYMENT_METHOD')
    @api.doc('search door based on post parameters')
    def post(self, page=0):
        app.logger.info('Search payment_method method called')
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
            payment_method_list = []
            for hit in response['hits']['hits']:
                payment_method = hit['_source']
                payment_method['id'] = hit['_id']
                payment_method_list.append(payment_method)
            app.logger.info('Search payment_method method completed')
            app.logger.debug('PAYMENT_METHOD LIST:')
            app.logger.debug(str(json.dumps(payment_method_list)))
            return payment_method_list, 200
        app.logger.error('Elasticsearch down, response: ' + str(response))
        return {'message': 'internal server error'}, 500

