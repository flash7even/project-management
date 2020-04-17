import json
from datetime import date
import datetime
import requests
from flask import current_app as app


_http_headers = {'Content-Type': 'application/json'}

_es_index = 'pms_materials'
_es_type = '_doc'
_es_size = 100

ENTRY = 'ENTRY'
STOCK = 'STOCK'


def get_current_date():
    today = datetime.datetime.today()
    today_date = date(year=today.year, month=today.month, day=today.day)
    return today_date


def get_material_report(material_name, project_name):
    app.logger.info('Search material report method called')
    rs = requests.session()
    query_json = {'query': {'match_all': {}}}
    must = []

    must.append({'term': {'reference': STOCK}})
    if material_name:
        must.append({'term': {'material_name': material_name}})
    if project_name:
        must.append({'term': {'project_name': project_name}})

    if len(must) > 0:
        query_json = {'query': {'bool': {'must': must}}}

    query_json['size'] = _es_size
    search_url = 'http://{}/{}/{}/_search'.format(app.config['ES_HOST'], _es_index, _es_type)

    app.logger.debug('query_json: ' + json.dumps(query_json))

    response = rs.post(url=search_url, json=query_json, headers=_http_headers).json()
    app.logger.debug('response: ' + json.dumps(response))

    material_data = {
        'total_price': 0,
        'total_quantity': 0,
    }

    if 'hits' in response:
        for hit in response['hits']['hits']:
            data = hit['_source']
            material_data['total_price'] += float(data['total_price'])
            material_data['total_quantity'] += float(data['quantity'])
        app.logger.debug('material_data: ' + json.dumps(material_data))
        app.logger.info('Search material report method completed')
        return material_data
    app.logger.error('Elasticsearch down, response: ' + str(response))
    return material_data