import json
from datetime import date
import datetime

import requests
from flask import current_app as app

_http_headers = {'Content-Type': 'application/json'}

_es_index = 'pms_transactions'
_es_type = '_doc'
_es_size = 500


def find_transaction_list_using_search_params(param):
    app.logger.info('Search project method called')
    rs = requests.session()
    query_json = {'query': {'match_all': {}}}
    must = []
    payment_date_start = "1970-01-01"
    payment_date_end = str(date.today())

    for f in param:
        if f == 'project_name' and param[f] != 'ALL':
            must.append({'term': {f: param[f]}})
        if f == 'payment_date_start' and param[f]:
            payment_date_start = param[f]
        if f == 'payment_date_end' and param[f]:
            payment_date_end = param[f]

    must.append({"range": {"payment_date": {"gte": payment_date_start, "lte": payment_date_end}}})

    if len(must) > 0:
        query_json = {'query': {'bool': {'must': must}}}

    query_json['size'] = _es_size
    search_url = 'http://{}/{}/{}/_search'.format(app.config['ES_HOST'], _es_index, _es_type)

    response = rs.post(url=search_url, json=query_json, headers=_http_headers).json()
    project_list = []
    if 'hits' in response:
        for hit in response['hits']['hits']:
            project = hit['_source']
            project['id'] = hit['_id']
            project_list.append(project)
        app.logger.info('Search project method completed')
        app.logger.debug('Transaction List:')
        app.logger.debug(str(json.dumps(project_list)))
        return project_list
    app.logger.error('Elasticsearch down, response: ' + str(response))
    return project_list


def get_transaction_initial_time():
    app.logger.info('get_transaction_initial_time method called')
    rs = requests.session()
    initial_time = datetime.date.today()
    query_json = {'sort': [{'payment_date': {'order': 'asc'}}] ,'query': {'match_all': {}}}
    query_json['size'] = 1
    search_url = 'http://{}/{}/{}/_search'.format(app.config['ES_HOST'], _es_index, _es_type)

    response = rs.post(url=search_url, json=query_json, headers=_http_headers).json()
    if 'hits' in response:
        for hit in response['hits']['hits']:
            data = hit['_source']
            initial_time = data['payment_date']
            initial_time = datetime.datetime.strptime(initial_time, '%Y-%m-%d')
            return initial_time.date()
    app.logger.error('Elasticsearch down, response: ' + str(response))
    app.logger.info('get_transaction_initial_time method completed')
    return initial_time


def find_transaction_stat(project_id):
    app.logger.info('Find transaction stat of project details method called')
    rs = requests.session()
    must = [{'term': {'project_id': project_id}}]
    query_json = {'query': {'bool': {'must': must}}}
    query_json['size'] = _es_size
    search_url = 'http://{}/{}/{}/_search'.format(app.config['ES_HOST'], _es_index, _es_type)

    response = rs.post(url=search_url, json=query_json, headers=_http_headers).json()
    transaction_count = 0
    transaction_amount = 0
    if 'hits' in response:
        for hit in response['hits']['hits']:
            transaction_count += 1
            data = hit['_source']
            transaction_amount += float(data['amount'])
        return {
            'transaction_count': transaction_count,
            'transaction_amount': transaction_amount
        }
    app.logger.error('Elasticsearch down, response: ' + str(response))
    return None


def find_transaction_balance_sheet(search_param):
    transaction_list = find_transaction_list_using_search_params(search_param)

    tran_sheet = {
        'debit_amount': 0,
        'credit_amount': 0
    }

    for tran in transaction_list:
        if tran.get('transaction_type', '') == 'Debit':
            tran_sheet['debit_amount'] += float(tran['amount'])
        if tran.get('transaction_type', '') == 'Credit':
            tran_sheet['credit_amount'] += float(tran['amount'])

    tran_sheet['transaction_balance'] = tran_sheet['credit_amount'] - tran_sheet['debit_amount']
    return tran_sheet
