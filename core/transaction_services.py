import json

import requests
from flask import current_app as app

_http_headers = {'Content-Type': 'application/json'}

_es_index = 'pms_transactions'
_es_type = '_doc'
_es_size = 500


def find_transaction_list_using_search_params(search_param):
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
        app.logger.debug('Transaction List:')
        app.logger.debug(str(json.dumps(project_list)))
        return project_list
    app.logger.error('Elasticsearch down, response: ' + str(response))
    return project_list


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
