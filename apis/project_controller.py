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

api = Namespace('device', description='Namespace for device service')

_http_headers = {'Content-Type': 'application/json'}

_es_index = 'tardy_devices'
_es_type = 'device'
_es_door_device_index = 'tardy_door_device_control'
_es_door_device_type = 'control'
_es_size = 100
active = 'active'
deleted = 'deleted'
mandatory_fields = ["device_name", "device_type", "ip_address"]
door_mandatory_fields = ["device_id", "door_id"]
device_type_list = ['entry_door', 'exit_door', 'indoor', 'outdoor']

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


def get_device_from_device_door(device_id):
    rs = requests.session()
    app.logger.info('Search door information for the current device')
    query_json = {'query': {'bool': {'must': {'match': {'device_id': device_id}}}}}
    app.logger.debug('query_json: ' + str(json.dumps(query_json)))
    search_url = 'http://{}/{}/{}/_search'.format(app.config['ES_HOST'], _es_door_device_index, _es_door_device_type)
    response = rs.post(url=search_url, json=query_json, headers=_http_headers).json()
    app.logger.debug('Response: ' + str(response))

    if 'hits' in response:
        for hit in response['hits']['hits']:
            return hit['_source']
    return None


@api.route('/<string:device_id>')
class DeviceByID(Resource):

    @access_required(access='CREATE_DEVICE DELETE_DEVICE UPDATE_DEVICE SEARCH_DEVICE VIEW_DEVICE')
    @api.doc('get device details by id')
    def get(self, device_id):
        app.logger.info('Get device_details method called')
        rs = requests.session()
        search_url = 'http://{}/{}/{}/{}'.format(app.config['ES_HOST'], _es_index, _es_type, device_id)
        response = rs.get(url=search_url, headers=_http_headers).json()
        if 'found' in response:
            if response['found']:
                data = response['_source']
                data['id'] = response['_id']
                app.logger.info('Get device_details method completed')
                data['assigned_status'] = False
                door_device_data = get_device_from_device_door(data['id'])
                if door_device_data:
                    data['assigned_status'] = True
                return data, 200
            app.logger.warning('Device not found')
            return {'found': response['found']}, 404
        app.logger.error('Elasticsearch down, response: ' + str(response))
        return response, 500

    @access_required(access='CREATE_DEVICE DELETE_DEVICE UPDATE_DEVICE')
    @api.doc('update device by id')
    def put(self, device_id):
        app.logger.info('Update device_details method called')
        current_user = get_jwt_identity().get('id')
        rs = requests.session()
        post_data = request.get_json()
        search_url = 'http://{}/{}/{}/{}'.format(app.config['ES_HOST'], _es_index, _es_type, device_id)
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
                    app.logger.info('Update device_details method completed')
                    return response['result'], 200
            app.logger.warning('Device not found')
            return {'message': 'not found'}, 404
        app.logger.error('Elasticsearch down, response: ' + str(response))
        return response, 500

    @access_required(access='DELETE_DEVICE')
    @api.doc('delete device by id')
    def delete(self, device_id):
        app.logger.info('Delete device_details method called')
        rs = requests.session()
        search_url = 'http://{}/{}/{}/{}'.format(app.config['ES_HOST'], _es_index, _es_type, device_id)
        response = rs.delete(url=search_url, headers=_http_headers).json()
        print('response: ', response)
        if 'found' in response:
            delete_query = {'query': {'bool': {'must': [{'term': {'device_id': device_id}}]}}}
            delete_url = 'http://{}/{}/{}/_delete_by_query'.format(app.config['ES_HOST'], _es_door_device_index, _es_door_device_type)
            app.logger.debug('Elasticsearch query : ' + str(delete_query))
            rs.post(url=delete_url, json=delete_query, headers=_http_headers).json()
            app.logger.debug('Elasticsearch response : ' + str(response))
            app.logger.info('Delete device_details method completed')
            return response['result'], 200
        app.logger.error('Elasticsearch down, response: ' + str(response))
        return response, 500


@api.route('/')
class CreateDevice(Resource):

    @access_required(access='CREATE_DEVICE DELETE_DEVICE')
    @api.doc('create new device')
    def post(self):
        app.logger.info('Create device method called')
        current_user = get_jwt_identity().get('id')
        rs = requests.session()
        data = request.get_json()

        for field in mandatory_fields:
            if field not in data:
                app.logger.warning('required fields are missing')
                return {"message": "required fields are missing"}, 400

        if data['device_type'] not in device_type_list:
            return {'message': 'device_type is invalid'}, 400

        query_json = {'query': {'bool': {'must': [{'term': {'ip_address': data['ip_address']}}]}}}
        query_json['size'] = 1
        search_url = 'http://{}/{}/{}/_search'.format(app.config['ES_HOST'], _es_index, _es_type)
        response = requests.session().post(url=search_url, json=query_json, headers=_http_headers).json()

        if 'hits' in response:
            if len(response['hits']['hits']) > 0:
                return {'message': 'ip_address is already assigned to a device'}, 400

        data['created_by'] = current_user
        data['created_at'] = int(time.time())
        data['updated_by'] = current_user
        data['updated_at'] = int(time.time())
        post_url = 'http://{}/{}/{}'.format(app.config['ES_HOST'], _es_index, _es_type)
        response = rs.post(url=post_url, json=data, headers=_http_headers).json()

        if 'created' in response:
            if response['created']:
                app.logger.info('Create device method completed')
                return response['_id'], 201
        app.logger.error('Elasticsearch down, response: ' + str(response))
        return response, 500


@api.route('/search', defaults={'page': 0})
@api.route('/search/<int:page>')
class SearchDevice(Resource):

    @access_required(access='CREATE_DEVICE DELETE_DEVICE UPDATE_DEVICE SEARCH_DEVICE VIEW_DEVICE')
    @api.doc('search door based on post parameters')
    def post(self, page=0):
        app.logger.info('Search device method called')
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
            data = []
            for hit in response['hits']['hits']:
                device = hit['_source']
                device['id'] = hit['_id']
                device['assigned_status'] = False
                door_device_data = get_device_from_device_door(device['id'])
                if door_device_data:
                    device['assigned_status'] = True
                data.append(device)
            app.logger.info('Search device method completed')
            return data, 200
        app.logger.error('Elasticsearch down, response: ' + str(response))
        return {'message': 'internal server error'}, 500


"""
@api.route('/door')
class AddDoor(Resource):

    @access_required(access='CREATE_DEVICE DELETE_DEVICE')
    @api.doc('Add door to device')
    def post(self):
        app.logger.info('Add door to device method called')
        current_user = get_jwt_identity().get('id')
        rs = requests.session()
        data = request.get_json()

        for field in door_mandatory_fields:
            if field not in data:
                app.logger.warning('required fields are missing')
                return {"message": "required fields are missing"}, 400

        query_json = {'query': {'bool': {'must': [{'term': {'device_id': data['device_id']}}]}}}
        query_json['size'] = 1
        search_url = 'http://{}/{}/{}/_search'.format(app.config['ES_HOST'], _es_door_device_index, _es_door_device_type)
        response = requests.session().post(url=search_url, json=query_json, headers=_http_headers).json()

        if 'hits' in response:
            if len(response['hits']['hits']) > 0:
                return {'message': 'device is already connected to a door'}, 400

        data['created_by'] = current_user
        data['created_at'] = int(time.time())
        data['updated_by'] = current_user
        data['updated_at'] = int(time.time())
        post_url = 'http://{}/{}/{}'.format(app.config['ES_HOST'], _es_door_device_index, _es_door_device_type)
        response = rs.post(url=post_url, json=data, headers=_http_headers).json()

        if 'created' in response:
            if response['created']:
                app.logger.info('Add door to device method completed')
                return response['_id'], 201
        app.logger.error('Elasticsearch down, response: ' + str(response))
        return response, 500
"""


@api.route('/door')
class AddDoor(Resource):

    @access_required(access='CREATE_DEVICE DELETE_DEVICE')
    @api.doc('Add door to device')
    def post(self):
        app.logger.info('Add door to device method called')
        current_user = get_jwt_identity().get('id')
        rs = requests.session()
        data = request.get_json()

        if 'door_id' not in data or 'device_list' not in data:
            app.logger.warning('required fields are missing')
            return {"message": "required fields are missing"}, 400

        for device_id in data['device_list']:
            query_json = {'query': {'bool': {'must': [{'term': {'device_id': device_id}}]}}}
            query_json['size'] = _es_size
            search_url = 'http://{}/{}/{}/_search'.format(app.config['ES_HOST'], _es_door_device_index, _es_door_device_type)
            response = rs.post(url=search_url, json=query_json, headers=_http_headers).json()
            if 'hits' in response:
                for hit in response['hits']['hits']:
                    if hit['_source']['door_id'] != data['door_id']:
                        return {'message': 'device is already connected to a door'}, 400

        delete_query = {'query': {'bool': {'must': [{'term': {'door_id': data['door_id']}}]}}}
        delete_url = 'http://{}/{}/{}/_delete_by_query'.format(app.config['ES_HOST'], _es_door_device_index, _es_door_device_type)
        app.logger.debug('Elasticsearch query : ' + str(delete_query))
        response = rs.post(url=delete_url, json=delete_query, headers=_http_headers).json()
        app.logger.debug('Elasticsearch response : ' + str(response))
        door_device_id_list = []

        for device_id in data['device_list']:
            device_door_data = {
                'device_id': device_id,
                'door_id': data['door_id']
            }
            device_door_data['created_by'] = current_user
            device_door_data['created_at'] = int(time.time())
            device_door_data['updated_by'] = current_user
            device_door_data['updated_at'] = int(time.time())

            post_url = 'http://{}/{}/{}/'.format(app.config['ES_HOST'], _es_door_device_index, _es_door_device_type)
            app.logger.debug('Elasticsearch query : ' + str(post_url))
            response = rs.post(url=post_url, json=device_door_data, headers=_http_headers).json()
            app.logger.debug('Elasticsearch response :' + str(response))

            if 'created' not in response:
                app.logger.error('Elasticsearch down, response: ' + str(response))
                return response, 500
            if response['created']:
                door_device_id_list.append(response['_id'])

        app.logger.info('Create institution for user service completed')
        return door_device_id_list, 200


@api.route('/door/delete/<string:door_id>/<string:device_id>')
class DeleteDoor(Resource):

    @access_required(access='DELETE_DEVICE')
    @api.doc('Delete device from door')
    def delete(self, door_id, device_id):
        app.logger.info('Delete device from door method called')
        current_user = get_jwt_identity().get('id')
        rs = requests.session()
        must = []
        must.append({'term': {'device_id': device_id}})
        must.append({'term': {'door_id': door_id}})

        query_json = {}
        if len(must) > 0:
            query_json = {'query': {'bool': {'must': must}}}

        query_json['size'] = _es_size
        search_url = 'http://{}/{}/{}/_search'.format(app.config['ES_HOST'], _es_door_device_index, _es_door_device_type)

        response = rs.post(url=search_url, json=query_json, headers=_http_headers).json()
        if 'hits' in response:
            data = []
            for hit in response['hits']['hits']:
                doc_id = hit['_id']
                delete_url = 'http://{}/{}/{}/{}'.format(app.config['ES_HOST'], _es_door_device_index,
                                                              _es_door_device_type, doc_id)
                response = rs.delete(url=delete_url, headers=_http_headers).json()
                if 'found' not in response:
                    app.logger.error('Elasticsearch down, response: ' + str(response))
                    return response, 500
                data.append(doc_id)
            app.logger.info('Delete device from door method completed')
            return data, 200
        app.logger.error('Elasticsearch down, response: ' + str(response))
        return {'message': 'internal server error'}, 500



@api.route('/dtsearch')
class SearchDeviceDT(Resource):

    @access_required(access='CREATE_DEVICE DELETE_DEVICE UPDATE_DEVICE SEARCH_DEVICE VIEW_DEVICE')
    @api.doc('search users based on query parameters')
    def get(self):
        app.logger.info('DT search device method called')
        param = request.args.to_dict()
        for key in param:
            param[key] = param[key].replace('"', '')

        pageIndex = 0
        pageSize = _es_size

        if 'pageIndex' in param:
            pageIndex = int(param['pageIndex'])

        if 'pageSize' in param:
            pageSize = int(param['pageSize'])

        should = []

        if 'filter' in param and param['filter']:
            should.append({'match': {'device_id': param['filter']}})
            should.append({'match': {'device_model': param['filter']}})
            should.append({'match': {'device_name': param['filter']}})
            should.append({'match': {'device_type': param['filter']}})
            should.append({'match': {'ip_address': param['filter']}})

        query = {'bool': {'should': should}}

        if len(should) == 0:
            query = {'match_all': {}}

        query_json = {'query': query, 'from': pageIndex * pageSize, 'size': pageSize}

        #if 'sortActive' in param:
        #    query_json['sort'] = [{param['sortActive']: {'order': param['sortOrder']}}]

        search_url = 'http://{}/{}/{}/_search'.format(app.config['ES_HOST'], _es_index, _es_type)
        response = requests.session().post(url=search_url, json=query_json, headers=_http_headers).json()

        if 'hits' in response:
            data = []
            for hit in response['hits']['hits']:
                device = hit['_source']
                device['id'] = hit['_id']
                device['assigned_status'] = False
                door_device_data = get_device_from_device_door(device['id'])
                if door_device_data:
                    device['assigned_status'] = True
                data.append(device)
            return_data = {
                'device_list': data,
                'count': response['hits']['total']
            }
            app.logger.info('DT search device method completed')
            return return_data, 200
        app.logger.error('Elasticsearch down, response: ' + str(response))
        return {'message': 'internal server error'}, 500
