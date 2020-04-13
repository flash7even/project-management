import json
from datetime import date
import datetime

import requests
from flask import current_app as app

_http_headers = {'Content-Type': 'application/json'}

_es_index = 'pms_bills'
_es_type = '_doc'
_es_size = 500


def find_bill_list_using_search_params(search_param):
    app.logger.info('Search project method called')
    rs = requests.session()
    query_json = {'query': {'match_all': {}}}
    must = []
    keyword_fields = []
    for field in search_param:
        if field in keyword_fields:
            must.append({'term': {field: search_param[field]}})
        else:
            must.append({'match': {field: search_param[field]}})

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
        app.logger.debug('Bill List:')
        app.logger.debug(str(json.dumps(project_list)))
        return project_list
    app.logger.error('Elasticsearch down, response: ' + str(response))
    return project_list


def get_bill_initial_time():
    app.logger.info('get_bill_initial_time method called')
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
    app.logger.info('get_bill_initial_time method completed')
    return initial_time


def find_bill_stat(project_id):
    app.logger.info('Find bill stat of project details method called')
    rs = requests.session()
    must = [{'term': {'project_id': project_id}}]
    query_json = {'query': {'bool': {'must': must}}}
    query_json['size'] = _es_size
    search_url = 'http://{}/{}/{}/_search'.format(app.config['ES_HOST'], _es_index, _es_type)

    response = rs.post(url=search_url, json=query_json, headers=_http_headers).json()
    bill_count = 0
    bill_amount = 0
    if 'hits' in response:
        for hit in response['hits']['hits']:
            bill_count += 1
            data = hit['_source']
            bill_amount += float(data['amount_received'])
        return {
            'bill_count': bill_count,
            'bill_amount': bill_amount
        }
    app.logger.error('Elasticsearch down, response: ' + str(response))
    return None
