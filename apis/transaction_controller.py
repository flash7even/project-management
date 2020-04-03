import requests, time, json
from datetime import date
import datetime
from flask import current_app as app
from flask import request
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended.exceptions import *
from flask_restplus import Namespace, Resource
from jwt.exceptions import *

from core.project_services import find_project_list_using_search_params, get_current_date
from core.transaction_services import cleanify_transaction_data, get_transaction_initial_time

api = Namespace('transaction', description='Namespace for transaction service')

_http_headers = {'Content-Type': 'application/json'}

_es_index = 'pms_transactions'
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


@api.route('/<string:transaction_id>')
class TransactionByID(Resource):

    #@access_required(access='CREATE_TRANSACTION DELETE_TRANSACTION UPDATE_TRANSACTION SEARCH_TRANSACTION VIEW_TRANSACTION')
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
    @api.doc('update transaction by id')
    def put(self, transaction_id):
        app.logger.info('Update transaction_details method called')
        #current_user = get_jwt_identity().get('id')
        rs = requests.session()
        post_data = request.get_json()
        search_url = 'http://{}/{}/{}/{}'.format(app.config['ES_HOST'], _es_index, _es_type, transaction_id)
        response = rs.get(url=search_url, headers=_http_headers).json()
        app.logger.debug('es response: ' + str(response))
        if 'found' in response:
            if response['found']:
                data = response['_source']
                for key in post_data:
                    if post_data[key]:
                        data[key] = post_data[key]
                #data['updated_by'] = current_user
                data['updated_at'] = str(get_current_date())
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
    def delete(self, transaction_id):
        app.logger.info('Delete transaction_details method called, transaction_id: ' + str(transaction_id))
        rs = requests.session()
        search_url = 'http://{}/{}/{}/{}'.format(app.config['ES_HOST'], _es_index, _es_type, transaction_id)
        response = rs.delete(url=search_url, headers=_http_headers).json()
        if 'result' in response:
            return response['result'], 200
        app.logger.error('Elasticsearch down, response: ' + str(response))
        return response, 500


@api.route('/')
class CreateTransaction(Resource):

    #@access_required(access='CREATE_TRANSACTION DELETE_TRANSACTION')
    @api.doc('create new transaction')
    def post(self):
        app.logger.info('Create transaction method called')
        #current_user = get_jwt_identity().get('id')
        rs = requests.session()
        data = request.get_json()

        mandatory_fields = ['transaction_id', 'amount', 'project_name']

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

        #data['created_at'] = str(get_current_date())
        data['updated_at'] = str(get_current_date())
        data['active_status'] = 'active'

        app.logger.info('data' + json.dumps(data))
        post_url = 'http://{}/{}/{}'.format(app.config['ES_HOST'], _es_index, _es_type)
        response = rs.post(url=post_url, json=data, headers=_http_headers).json()

        if 'result' in response and response['result'] == 'created':
            app.logger.info('Create transaction method completed')
            return response['_id'], 201
        app.logger.error('Elasticsearch down, response: ' + str(response))
        return response, 500


@api.route('/search', defaults={'page': 0})
@api.route('/search/<int:page>')
class SearchTransaction(Resource):

    #@access_required(access='CREATE_TRANSACTION DELETE_TRANSACTION UPDATE_TRANSACTION SEARCH_TRANSACTION VIEW_TRANSACTION')
    @api.doc('search door based on post parameters')
    def post(self, page=0):
        app.logger.info('Search transaction method called')
        param = request.get_json()
        app.logger.debug('params: ' + str(json.dumps(param)))
        query_json = {'query': {'match_all': {}}}
        must = []
        must.append({'term': {'active_status': 'active'}})
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

        query_json['sort'] = [{'payment_date': {'order': 'asc'}}]
        app.logger.debug('query_json: ' + str(json.dumps(query_json)))

        search_url = 'http://{}/{}/{}/_search'.format(app.config['ES_HOST'], _es_index, _es_type)

        response = requests.session().post(url=search_url, json=query_json, headers=_http_headers).json()
        if 'hits' in response:
            transaction_list = []
            for hit in response['hits']['hits']:
                transaction = hit['_source']
                transaction['id'] = hit['_id']
                transaction = cleanify_transaction_data(transaction)
                transaction_list.append(transaction)
            app.logger.debug('final list: ' + str(json.dumps(transaction_list)))
            app.logger.info('Search transaction method completed')
            return transaction_list, 200
        app.logger.error('Elasticsearch down, response: ' + str(response))
        return {'message': 'internal server error'}, 500


@api.route('/statsperweek/<int:week>')
class StatsPerWeek(Resource):

    #@access_required(access='CREATE_TRANSACTION DELETE_TRANSACTION UPDATE_TRANSACTION SEARCH_TRANSACTION VIEW_TRANSACTION')
    @api.doc('statistics per week')
    def post(self, week):
        app.logger.info('STATISTICS PER WEEK for transaction called')
        param = request.get_json()
        curtime = int(time.time())
        stats_list = []
        for w in range(0, week):
            prevtime = curtime - 604800
            prevtime_dt = time.strftime('%Y-%m-%d', time.localtime(prevtime))
            curtime_dt = time.strftime('%Y-%m-%d', time.localtime(curtime))
            must = []
            must.append({"range": {"payment_date": {"gte": prevtime_dt,"lte": curtime_dt}}})
            must.append({'term': {'active_status': 'active'}})
            if param is not None and 'project_id' in param:
                must.append({"term" : {"project_id" : param["project_id"]}})
            query_json = {"query": {"bool" : {"must" : must}}}
            search_url = 'http://{}/{}/{}/_search'.format(app.config['ES_HOST'], _es_index, _es_type)
            rs = requests.session()
            response = rs.post(url=search_url, json=query_json, headers=_http_headers).json()
            app.logger.info('query_json: ' + json.dumps(query_json))
            app.logger.info('response: ' + json.dumps(response))
            if 'hits' in response:
                no_of_tx = 0
                total_amount = 0
                for hit in response['hits']['hits']:
                    transaction = hit['_source']
                    no_of_tx += 1
                    total_amount += float(transaction['amount'])
                data = {}
                data["total_transaction"] = no_of_tx
                data["total_amount_of_transactions"] = total_amount
                stats_list.append(data)
                curtime = prevtime
            else:
                app.logger.error('Elasticsearch down, response: ' + str(response))
                return {'message': 'internal server error'}, 500
        app.logger.info('WEEKLY_STAT: ' + json.dumps(stats_list))
        app.logger.info('Statistics per week for transaction completed')
        return stats_list, 200


@api.route('/statsperweek/perproject/<int:division>')
class StatsPerWeek(Resource):

    #@access_required(access='CREATE_TRANSACTION DELETE_TRANSACTION UPDATE_TRANSACTION SEARCH_TRANSACTION VIEW_TRANSACTION')
    @api.doc('Project statistics per division')
    def post(self, division):
        app.logger.info('STATISTICS PER DIVISION PER PROJECT for transaction called')

        initial_date = get_transaction_initial_time()
        current_date = date.today()
        total_days = (current_date - initial_date).days
        app.logger.info('total_days: ' + str(total_days))
        avg_days_per_division = int(total_days/division)
        app.logger.info('total_days: ' + str(avg_days_per_division))

        project_list = find_project_list_using_search_params({})
        app.logger.info('project_list: ' + json.dumps(project_list))

        stats_list = {
            'project_list': project_list,
            'interval_duration': avg_days_per_division,
            'data_list_per_division': []
        }

        date_now = initial_date
        for d in range(0, division):
            date_now = date_now + datetime.timedelta(days=avg_days_per_division)
            app.logger.info('date_now: ' + str(date_now))

            project_data_list = []

            for project in project_list:

                must = []
                must.append({"range": {"payment_date": {"gte": str(initial_date), "lte": str(date_now)}}})
                must.append({'term': {'active_status': 'active'}})
                must.append({"term": {"project_id": project["id"]}})
                query_json = {"query": {"bool" : {"must" : must}}}
                query_json['aggs'] = {"amount" : { "sum" : { "field" : "amount" }}}
                query_json['size'] = 0

                search_url = 'http://{}/{}/{}/_search'.format(app.config['ES_HOST'], _es_index, _es_type)
                rs = requests.session()
                app.logger.debug('query_json: ' + str(json.dumps(query_json)))
                response = rs.post(url=search_url, json=query_json, headers=_http_headers).json()
                app.logger.info('response: ' + json.dumps(response))

                if 'hits' in response and 'aggregations' in response:
                    pdata = {
                        'amount_sum': response['aggregations']['amount']['value']
                    }
                    project_data_list.append(pdata)
                else:
                    app.logger.error('Elasticsearch down, response: ' + str(response))
                    return {'message': 'internal server error'}, 500

            div_data = {
                'end_date': str(date_now),
                'project_data_list': project_data_list
            }
            stats_list['data_list_per_division'].append(div_data)

        app.logger.info('DIVISION_WISE_STAT: ' + json.dumps(stats_list))
        app.logger.info('Statistics per division per project for transaction completed')
        return stats_list, 200


@api.route('/status/<string:transaction_id>/<string:status>')
class TransactionByID(Resource):

    @api.doc('update transaction by id')
    def put(self, transaction_id, status):
        app.logger.info('Update transaction_details method called')
        #current_user = get_jwt_identity().get('id')
        rs = requests.session()
        search_url = 'http://{}/{}/{}/{}'.format(app.config['ES_HOST'], _es_index, _es_type, transaction_id)
        response = rs.get(url=search_url, headers=_http_headers).json()
        app.logger.debug('es response: ' + str(response))
        if 'found' in response:
            if response['found']:
                data = response['_source']
                data['active_status'] = status
                data['updated_at'] = str(get_current_date())
                response = rs.put(url=search_url, json=data, headers=_http_headers).json()
                if 'result' in response:
                    app.logger.info('Update transaction_details method completed')
                    return response['result'], 200
            app.logger.warning('Transaction not found')
            return {'message': 'not found'}, 404
        app.logger.error('Elasticsearch down, response: ' + str(response))
        return response, 500
