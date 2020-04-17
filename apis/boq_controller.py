import time
import json
from datetime import date
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
from core.plibrary import find_document_id
from core.material_services import get_material_report

api = Namespace('boq', description='Namespace for boq service')

_http_headers = {'Content-Type': 'application/json'}

_es_index = 'pms_boq'
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


@api.route('/<string:boq_id>')
class BOQByID(Resource):

    #@access_required(access='CREATE_BOQ DELETE_BOQ UPDATE_BOQ SEARCH_BOQ VIEW_BOQ')
    @api.doc('get boq details by id')
    def get(self, boq_id):
        app.logger.info('Get boq_details api called')
        rs = requests.session()
        search_url = 'http://{}/{}/{}/{}'.format(app.config['ES_HOST'], _es_index, _es_type, boq_id)
        response = rs.get(url=search_url, headers=_http_headers).json()
        if 'found' in response:
            if response['found']:
                data = response['_source']
                data['id'] = response['_id']
                app.logger.info('Get boq_details api completed')
                return data, 200
            app.logger.warning('BOQ not found')
            return {'found': response['found']}, 404
        app.logger.error('Elasticsearch down, response: ' + str(response))
        return response, 500

    #@access_required(access='CREATE_BOQ DELETE_BOQ UPDATE_BOQ')
    @api.doc('update boq by id')
    def put(self, boq_id):
        app.logger.info('Update boq_details api called')
        #current_user = get_jwt_identity().get('id')
        rs = requests.session()
        post_data = request.get_json()
        search_url = 'http://{}/{}/{}/{}'.format(app.config['ES_HOST'], _es_index, _es_type, boq_id)
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
                    app.logger.info('Update boq_details api completed')
                    return response['result'], 200
            app.logger.warning('BOQ not found')
            return {'message': 'not found'}, 404
        app.logger.error('Elasticsearch down, response: ' + str(response))
        return response, 500

    #@access_required(access='DELETE_BOQ')
    @api.doc('delete boq by id')
    def delete(self, boq_id):
        app.logger.info('Delete boq_details api called')
        rs = requests.session()
        search_url = 'http://{}/{}/{}/{}'.format(app.config['ES_HOST'], _es_index, _es_type, boq_id)
        response = rs.delete(url=search_url, headers=_http_headers).json()
        print('response: ', response)
        if 'result' in response and response['result'] == 'deleted':
            return response['result'], 200
        app.logger.error('Elasticsearch down, response: ' + str(response))
        return response, 500


@api.route('/')
class CreateBOQ(Resource):

    #@access_required(access='CREATE_BOQ DELETE_BOQ')
    @api.doc('create new boq')
    def post(self):
        app.logger.info('Create boq api called')
        #current_user = get_jwt_identity().get('id')
        rs = requests.session()
        data = request.get_json()

        app.logger.debug("CREATE BOQ DATA: " + json.dumps(data))
        data['created_at'] = int(time.time())
        data['updated_at'] = int(time.time())

        data['boq_id'] = find_document_id(data['project_name'], 8, 6)

        post_url = 'http://{}/{}/{}'.format(app.config['ES_HOST'], _es_index, _es_type)
        response = rs.post(url=post_url, json=data, headers=_http_headers).json()
        app.logger.debug('ES Response: ' + str(response))

        if 'result' in response and response['result'] == 'created':
            app.logger.info('Create boq api completed')
            return response['_id'], 201
        app.logger.error('Elasticsearch down, response: ' + str(response))
        return response, 500


@api.route('/search', defaults={'page': 0})
@api.route('/search/<int:page>')
class SearchBOQ(Resource):

    #@access_required(access='CREATE_BOQ DELETE_BOQ UPDATE_BOQ SEARCH_BOQ VIEW_BOQ')
    @api.doc('search door based on post parameters')
    def post(self, page=0):
        app.logger.info('Search boq api called')
        param = request.get_json()
        query_json = {'query': {'match_all': {}}}
        must = []
        issue_date_start = "1970-01-01"
        issue_date_end = str(date.today())

        for f in param:
            if f == 'project_name' and param[f] != 'ALL':
                must.append({'term': {f: param[f]}})
            if f == 'issue_date_start' and param[f]:
                issue_date_start = param[f]
            if f == 'issue_date_end' and param[f]:
                issue_date_end = param[f]

        must.append({"range": {"issue_date": {"gte": issue_date_start, "lte": issue_date_end}}})

        if len(must) > 0:
            query_json = {'query': {'bool': {'must': must}}}

        query_json['from'] = page * _es_size
        query_json['size'] = _es_size
        print('query_json: ' + str(json.dumps(query_json)))
        search_url = 'http://{}/{}/{}/_search'.format(app.config['ES_HOST'], _es_index, _es_type)

        response = requests.session().post(url=search_url, json=query_json, headers=_http_headers).json()
        if 'hits' in response:
            boq_list = []
            for hit in response['hits']['hits']:
                boq = hit['_source']
                boq['id'] = hit['_id']
                boq_list.append(boq)
            app.logger.info('Search boq api completed')
            print('BOQ List: ' + str(json.dumps(boq_list)))
            return boq_list, 200
        app.logger.error('Elasticsearch down, response: ' + str(response))
        return {'message': 'internal server error'}, 500


@api.route('/report', defaults={'page': 0})
@api.route('/report/<int:page>')
class SearchBOQ(Resource):

    #@access_required(access='CREATE_BOQ DELETE_BOQ UPDATE_BOQ SEARCH_BOQ VIEW_BOQ')
    @api.doc('search door based on post parameters')
    def post(self, page=0):
        app.logger.info('Search boq report api called')
        param = request.get_json()
        query_json = {'query': {'match_all': {}}}
        must = []
        issue_date_start = "1970-01-01"
        issue_date_end = str(date.today())

        for f in param:
            if f == 'project_name' and param[f] != 'ALL':
                must.append({'term': {f: param[f]}})
            if f == 'issue_date_start' and param[f]:
                issue_date_start = param[f]
            if f == 'issue_date_end' and param[f]:
                issue_date_end = param[f]

        must.append({"range": {"issue_date": {"gte": issue_date_start, "lte": issue_date_end}}})

        if len(must) > 0:
            query_json = {'query': {'bool': {'must': must}}}

        query_json['from'] = page * _es_size
        query_json['size'] = _es_size
        print('query_json: ' + str(json.dumps(query_json)))
        search_url = 'http://{}/{}/{}/_search'.format(app.config['ES_HOST'], _es_index, _es_type)

        response = requests.session().post(url=search_url, json=query_json, headers=_http_headers).json()
        if 'hits' in response:
            boq_list = []
            for hit in response['hits']['hits']:
                boq = hit['_source']
                material_report = get_material_report(boq['material_name'], boq['project_name'])
                boq['boq_set_total_price'] = boq['total_price']
                boq.pop('total_price', None)
                boq['boq_set_total_quantity'] = boq['quantity']
                boq.pop('quantity', None)

                for f in material_report:
                    boq[f] = material_report[f]

                boq_list.append(boq)
            app.logger.info('Search boq api completed')
            print('BOQ List: ' + str(json.dumps(boq_list)))
            return boq_list, 200
        app.logger.error('Elasticsearch down, response: ' + str(response))
        return {'message': 'internal server error'}, 500

