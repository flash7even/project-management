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
from core.transaction_services import find_transaction_stat, find_transaction_balance_sheet
from core.bill_services import find_bill_stat, find_bill_balance_sheet
from core.plibrary import find_document_id

api = Namespace('project', description='Namespace for project service')

_http_headers = {'Content-Type': 'application/json'}

_es_index = 'pms_projects'
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


@api.route('/<string:project_id>')
class ProjectByID(Resource):

    #@access_required(access='CREATE_PROJECT DELETE_PROJECT UPDATE_PROJECT SEARCH_PROJECT VIEW_PROJECT')
    @api.doc('get project details by id')
    def get(self, project_id):
        app.logger.info('Get project_details method called')
        rs = requests.session()
        search_url = 'http://{}/{}/{}/{}'.format(app.config['ES_HOST'], _es_index, _es_type, project_id)
        response = rs.get(url=search_url, headers=_http_headers).json()
        if 'found' in response:
            if response['found']:
                data = response['_source']
                data['id'] = response['_id']
                app.logger.info('Get project_details method completed')
                return data, 200
            app.logger.warning('Project not found')
            return {'found': response['found']}, 404
        app.logger.error('Elasticsearch down, response: ' + str(response))
        return response, 500

    #@access_required(access='CREATE_PROJECT DELETE_PROJECT UPDATE_PROJECT')
    @api.doc('update project by id')
    def put(self, project_id):
        app.logger.info('Update project_details method called')
        #current_user = get_jwt_identity().get('id')
        rs = requests.session()
        post_data = request.get_json()
        search_url = 'http://{}/{}/{}/{}'.format(app.config['ES_HOST'], _es_index, _es_type, project_id)
        response = rs.get(url=search_url, headers=_http_headers).json()
        if 'found' in response:
            if response['found']:
                data = response['_source']
                for key in post_data:
                    if post_data[key]:
                     data[key] = post_data[key]

                if 'time_extension' in post_data and post_data['time_extension']:
                    time_extension = int(post_data['time_extension'])
                    updated_date = datetime.datetime.strptime(data['adjusted_completion_date'], '%Y-%m-%d')
                    print(updated_date, type(updated_date))
                    updated_date = updated_date.date()
                    print(updated_date, type(updated_date))
                    updated_date = updated_date + datetime.timedelta(days=time_extension)
                    data['adjusted_completion_date'] = str(updated_date)

                data.pop('time_extension', None)

                #data['updated_by'] = current_user
                data['updated_at'] = str(datetime.date.today())
                response = rs.put(url=search_url, json=data, headers=_http_headers).json()
                print(response)
                if 'result' in response:
                    app.logger.info('Update project_details method completed')
                    return response['result'], 200
            app.logger.warning('Project not found')
            return {'message': 'not found'}, 404
        app.logger.error('Elasticsearch down, response: ' + str(response))
        return response, 500

    #@access_required(access='DELETE_PROJECT')
    @api.doc('delete project by id')
    def delete(self, project_id):
        app.logger.info('Delete project_details method called')
        rs = requests.session()
        search_url = 'http://{}/{}/{}/{}'.format(app.config['ES_HOST'], _es_index, _es_type, project_id)
        response = rs.delete(url=search_url, headers=_http_headers).json()
        print('response: ', response)
        if 'result' in response and response['result'] == 'deleted':
            return response['result'], 200
        app.logger.error('Elasticsearch down, response: ' + str(response))
        return response, 500


@api.route('/')
class CreateProject(Resource):

    #@access_required(access='CREATE_PROJECT DELETE_PROJECT')
    @api.doc('create new project')
    def post(self):
        app.logger.info('Create project method called')
        #current_user = get_jwt_identity().get('id')
        rs = requests.session()
        data = request.get_json()
        data['created_at'] = str(datetime.date.today())
        data['updated_at'] = str(datetime.date.today())
        data['project_id'] = find_document_id(data['project_name'], 8, 4)

        if 'completion_date' in data:
            data['adjusted_completion_date'] = data['completion_date']

        post_url = 'http://{}/{}/{}'.format(app.config['ES_HOST'], _es_index, _es_type)
        response = rs.post(url=post_url, json=data, headers=_http_headers).json()
        app.logger.debug('ES Response: ' + str(response))

        if 'result' in response and response['result'] == 'created':
            app.logger.info('Create project method completed')
            return response['_id'], 201
        app.logger.error('Elasticsearch down, response: ' + str(response))
        return response, 500


@api.route('/search', defaults={'page': 0})
@api.route('/search/<int:page>')
class SearchProject(Resource):

    #@access_required(access='CREATE_PROJECT DELETE_PROJECT UPDATE_PROJECT SEARCH_PROJECT VIEW_PROJECT')
    @api.doc('search door based on post parameters')
    def post(self, page=0):
        app.logger.info('Search project method called')
        param = request.get_json()
        query_json = {'query': {'match_all': {}}}
        must = []
        for fields in param:
            must.append({'match': {fields: param[fields]}})

        if len(must) > 0:
            query_json = {'query': {'bool': {'must': must}}}

        query_json['from'] = page * _es_size
        query_json['size'] = _es_size
        query_json['sort'] = [{'updated_at': {'order': 'desc'}}]
        search_url = 'http://{}/{}/{}/_search'.format(app.config['ES_HOST'], _es_index, _es_type)

        response = requests.session().post(url=search_url, json=query_json, headers=_http_headers).json()
        if 'hits' in response:
            project_list = []
            for hit in response['hits']['hits']:
                project = hit['_source']
                project['id'] = hit['_id']
                project_list.append(project)
            app.logger.info('Search project method completed')
            app.logger.debug('PROJECT LIST:')
            app.logger.debug(str(json.dumps(project_list)))
            return project_list, 200
        app.logger.error('Elasticsearch down, response: ' + str(response))
        return {'message': 'internal server error'}, 500


@api.route('/stats', defaults={'page': 0})
@api.route('/stats/<int:page>')
class SearchProjectStat(Resource):

    #@access_required(access='CREATE_PROJECT DELETE_PROJECT UPDATE_PROJECT SEARCH_PROJECT VIEW_PROJECT')
    @api.doc('search door based on post parameters')
    def post(self, page=0):
        app.logger.info('Project stat method called')
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
            project_list = []
            total_value = 0
            for hit in response['hits']['hits']:
                project = hit['_source']
                project['id'] = hit['_id']
                total_value += float(project['project_value'])
            for hit in response['hits']['hits']:
                project = hit['_source']
                project['id'] = hit['_id']
                own_val = float(project['project_value'])
                project['project_value_percentage'] = own_val*100/total_value
                project['transaction_stat'] = find_transaction_stat(project['id'])
                project['bill_stat'] = find_bill_stat(project['id'])
                project_list.append(project)
            app.logger.info('Search project stat method completed')
            app.logger.debug('PROJECT LIST:')
            app.logger.debug(str(json.dumps(project_list)))
            return project_list, 200
        app.logger.error('Elasticsearch down, response: ' + str(response))
        return {'message': 'internal server error'}, 500


@api.route('/balance/sheet', defaults={'page': 0})
@api.route('/balance/sheet/<int:page>')
class SearchProjectStat(Resource):

    #@access_required(access='CREATE_PROJECT DELETE_PROJECT UPDATE_PROJECT SEARCH_PROJECT VIEW_PROJECT')
    @api.doc('search door based on post parameters')
    def post(self, page=0):
        app.logger.info('Project balance sheet method called')
        param = request.get_json()
        data = {
            'transaction_sheet': find_transaction_balance_sheet(param),
            'bill_sheet': find_bill_balance_sheet(param)
        }
        app.logger.error('Project balance sheet method completed')
        return data, 200
