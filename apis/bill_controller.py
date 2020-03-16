import time
import json
import requests
from datetime import date
from flask import current_app as app
from flask import request
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended.exceptions import *
from flask_restplus import Namespace, Resource
from jwt.exceptions import *
from .auth_controller import access_required

from core.project_services import find_project_list_using_search_params

api = Namespace('bill', description='Namespace for bill service')

_http_headers = {'Content-Type': 'application/json'}

_es_index = 'pms_bills'
_es_type = '_doc'
_es_size = 100
INF = 9999999999999


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


@api.route('/<string:bill_id>')
class BillByID(Resource):

    @access_required(access='CREATE_BILL DELETE_BILL UPDATE_BILL SEARCH_BILL VIEW_BILL')
    @api.doc('get bill details by id')
    def get(self, bill_id):
        app.logger.info('Get bill_details method called')
        rs = requests.session()
        search_url = 'http://{}/{}/{}/{}'.format(app.config['ES_HOST'], _es_index, _es_type, bill_id)
        response = rs.get(url=search_url, headers=_http_headers).json()
        if 'found' in response:
            if response['found']:
                data = response['_source']
                data['id'] = response['_id']
                app.logger.info('Get bill_details method completed')
                return data, 200
            app.logger.warning('Bill not found')
            return {'found': response['found']}, 404
        app.logger.error('Elasticsearch down, response: ' + str(response))
        return response, 500

    @access_required(access='CREATE_BILL DELETE_BILL UPDATE_BILL')
    @api.doc('update bill by id')
    def put(self, bill_id):
        app.logger.info('Update bill_details method called')
        # current_user = get_jwt_identity().get('id')
        rs = requests.session()
        post_data = request.get_json()
        search_url = 'http://{}/{}/{}/{}'.format(app.config['ES_HOST'], _es_index, _es_type, bill_id)
        response = rs.get(url=search_url, headers=_http_headers).json()
        if 'found' in response:
            if response['found']:
                data = response['_source']
                for key, value in post_data.items():
                    data[key] = value
                data['updated_at'] = int(time.time())
                response = rs.put(url=search_url, json=data, headers=_http_headers).json()
                if 'result' in response:
                    app.logger.info('Update bill_details method completed')
                    return response['result'], 200
            app.logger.warning('Bill not found')
            return {'message': 'not found'}, 404
        app.logger.error('Elasticsearch down, response: ' + str(response))
        return response, 500

    @access_required(access='DELETE_BILL')
    @api.doc('delete bill by id')
    def delete(self, bill_id):
        app.logger.info('Delete bill_details method called')
        rs = requests.session()
        search_url = 'http://{}/{}/{}/{}'.format(app.config['ES_HOST'], _es_index, _es_type, bill_id)
        response = rs.delete(url=search_url, headers=_http_headers).json()
        print('response: ', response)
        if 'found' in response:
            return response['result'], 200
        app.logger.error('Elasticsearch down, response: ' + str(response))
        return response, 500


@api.route('/')
class CreateBill(Resource):

    @api.doc('create new bill')
    def post(self):
        app.logger.info('Create bill method called')
        # current_user = get_jwt_identity().get('id')
        rs = requests.session()
        data = request.get_json()

        mandatory_fields = ['bill_id', 'amount', 'project_name']

        for mfield in mandatory_fields:
            if mfield not in data:
                app.logger.warning('mandatory field missing')
                return {'message': 'mandatory field missing'}, 403

        project_params = {
            'project_name': data['project_name']
        }

        project_list = find_project_list_using_search_params(project_params)

        if len(project_list) != 1:
            return {'message': 'multiple project with same name'}, 403

        project_details = project_list[0]
        data['project_id'] = project_details['id']

        data['created_at'] = int(time.time())
        data['updated_at'] = int(time.time())

        post_url = 'http://{}/{}/{}'.format(app.config['ES_HOST'], _es_index, _es_type)
        response = rs.post(url=post_url, json=data, headers=_http_headers).json()

        if 'result' in response and response['result'] == 'created':
            app.logger.info('Create bill method completed')
            return response['_id'], 201
        app.logger.error('Elasticsearch down, response: ' + str(response))
        return response, 500


@api.route('/search', defaults={'page': 0})
@api.route('/search/<int:page>')
class SearchBill(Resource):

    #@access_required(access='CREATE_BILL DELETE_BILL UPDATE_BILL SEARCH_BILL VIEW_BILL')
    @api.doc('search bill based on post parameters')
    def post(self, page=0):
        app.logger.info('Search bill method called')
        param = request.get_json()
        app.logger.debug('params: ' + str(json.dumps(param)))
        query_json = {'query': {'match_all': {}}}
        must = []
        amount_min = 0
        amount_max = INF
        payment_date_start = "1970-01-01"
        payment_date_end = str(date.today())

        for f in param:
            if f == 'project_name' and param[f] != 'ALL':
                must.append({'term': {f: param[f]}})
            if f == 'amount_min' and param[f]:
                amount_min = param[f]
            if f == 'amount_max' and param[f]:
                amount_max = param[f]
            if f == 'payment_date_start' and param[f]:
                payment_date_start = param[f]
            if f == 'payment_date_end' and param[f]:
                payment_date_end = param[f]
            if f == 'status' and param[f] != 'ALL':
                must.append({'term': {f: param[f]}})
            if f == 'mode_of_payment' and param[f] != 'ALL':
                must.append({'match': {f: param[f]}})

        must.append({"range": {"payment_date": {"gte": payment_date_start, "lte": payment_date_end}}})
        must.append({"range": {"amount": {"gte": amount_min, "lte": amount_max}}})

        if len(must) > 0:
            query_json = {'query': {'bool': {'must': must}}}

        query_json['from'] = page * _es_size
        query_json['size'] = _es_size

        if 'sort_by' in param and param['sort_by'] != 'none':
            query_json['sort'] = [{param['sort_by']: {'order': param['sort_order']}}]

        app.logger.debug('query_json: ' + str(json.dumps(query_json)))

        search_url = 'http://{}/{}/{}/_search'.format(app.config['ES_HOST'], _es_index, _es_type)

        response = requests.session().post(url=search_url, json=query_json, headers=_http_headers).json()
        if 'hits' in response:
            bill_list = []
            for hit in response['hits']['hits']:
                bill = hit['_source']
                bill['id'] = hit['_id']
                bill_list.append(bill)
            app.logger.debug('final list: ' + str(json.dumps(bill_list)))
            app.logger.info('Search bill method completed')
            return bill_list, 200
        app.logger.error('Elasticsearch down, response: ' + str(response))
        return {'message': 'internal server error'}, 500



@api.route('/statsperweek/<int:week>')
class StatsPerWeek(Resource):

    #@access_required(access='CREATE_TRANSACTION DELETE_TRANSACTION UPDATE_TRANSACTION SEARCH_TRANSACTION VIEW_TRANSACTION')
    @api.doc('statistics per week')
    def post(self, week):
        app.logger.info('Statistics per week for bill called')
        param = request.get_json()
        curtime = int(time.time())
        stats_list = []
        for w in range(0, week):
            prevtime = curtime - 604800
            must = []
            must.append({"range": {"created_at": {"gte": prevtime,"lte": curtime}}})
            if param is not None and 'project_id' in param:
                must.append({"term" : {"project_id" : param["project_id"]}})
            query_json = {"query": {"bool" : {"must" : must}}}
            search_url = 'http://{}/{}/{}/_search'.format(app.config['ES_HOST'], _es_index, _es_type)
            rs = requests.session()
            response = rs.post(url=search_url, json=query_json, headers=_http_headers).json()
            if 'hits' in response:
                no_of_tx = 0
                total_amount = 0
                for hit in response['hits']['hits']:
                    bill = hit['_source']
                    no_of_tx += 1
                    total_amount += float(bill['amount'])
                data = {}
                data["total_bill"] = no_of_tx
                data["total_amount_of_bills"] = total_amount
                stats_list.append(data)
                curtime = prevtime
            else:
                app.logger.error('Elasticsearch down, response: ' + str(response))
                return {'message': 'internal server error'}, 500
        app.logger.info('Statistics per week for bill completed')
        return stats_list, 200