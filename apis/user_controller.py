import base64
import json
import random
import time
from datetime import timedelta
from hashlib import md5
from random import random
from PIL import Image

import requests
from flask import request, current_app as app
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended.exceptions import *
from flask_restplus import Namespace, Resource
from jwt.exceptions import *

from core.guest_service import pub_object
from .auth_controller import access_required
from .flask_minio import minio_client
from .guest_controller import store_image_v2, match_image_v2, upload_image, sanitize_word
from . import image_cropper

api = Namespace('user', description='user related services')

_local_recognize_url_endpoint = "/recognize/v2"

_http_headers = {'Content-Type': 'application/json'}
_es_index = 'tardy_users'
_es_type = 'user'
_es_role_index = 'tardy_user_role_lookup'
_es_role_type = 'role'
_es_index_device = 'tardy_devices'
_es_type_device = 'device'
_es_index_device_door = 'tardy_door_device_control'
_es_type_device_door = 'control'
_es_index_user_door = 'tardy_user_door_access'
_es_type_user_door = 'access'
_es_index_access_log = 'tardy_access_control_log'
_es_type_access_log = 'log'
_es_index_booth = 'tardy_booths'
_es_type_booth = 'booth'
_es_door_index = 'tardy_doors'
_es_door_type = 'door'

_es_size = 100
keywords = ["internal_id", "status"]
match_mandatory_fields = ['image_data', 'threshold', 'ip_address']
_es_src_filter = ["fullname"]

device_type_entry_door = 'entry_door'
device_type_exit_door = 'exit_door'
device_type_indoor = 'indoor'
device_type_outdoor = 'outdoor'

entry = 'entry'
exit = 'exit'
active = "active"
delete = "delete"
pending = 'pending'
unknown = 'unknown'
found = 'found'
unauthorized = 'unauthorized'
authorized = 'authorized'
user_hash_fields = ['fullname', 'phone']
image_rect_factor = 0.05


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


def get_user_details(user_id):
    app.logger.info('get_user_details method called')
    rs = requests.session()
    search_url = 'http://{}/{}/{}/{}'.format(app.config['ES_HOST'], _es_index, _es_type, user_id)
    response = rs.get(url=search_url, headers=_http_headers).json()
    if 'found' in response:
        if response['found']:
            app.logger.info('get_user_details method completed')
            return response['_source']
    else:
        app.logger.error('Elasticsearch down, response: ' + str(response))
        return response

    app.logger.info('No user found')
    return {}


def get_door_details(door_id):
    app.logger.info('get_door_details method called')
    rs = requests.session()
    search_url = 'http://{}/{}/{}/{}'.format(app.config['ES_HOST'], _es_door_index, _es_door_type, door_id)
    response = rs.get(url=search_url, headers=_http_headers).json()
    if 'found' in response:
        if response['found']:
            app.logger.info('get_door_details method completed')
            return response['_source']
    else:
        app.logger.error('Elasticsearch down, response: ' + str(response))
        return response
    app.logger.info('No door found')
    return {}


def get_device_from_ip_address(ip_address):
    app.logger.info('get_device_from_ip_address method called')
    rs = requests.session()
    search_url = 'http://{}/{}/{}/_search'.format(app.config['ES_HOST'], _es_index_device, _es_type_device)
    search_query = {'query': {'bool': {'must': [{'term': {'ip_address': ip_address}}]}}}
    response = rs.post(url=search_url, json=search_query, headers=_http_headers).json()

    if 'hits' not in response:
        app.logger.error('Elasticsearch down, response: ' + str(response))
        return None, {'message': 'internal server error'}, 500

    if response['hits']['total'] > 0:
        for hit in response['hits']['hits']:
            app.logger.info('get_device_from_ip_address method called')
            return hit['_source'], hit['_id'], 'device found', 200
    app.logger.info('No device found')
    return None, None, {"message": 'no device found'}, 404


def get_door_from_device_id(device_id):
    app.logger.info('get_door_from_device_id method called')
    rs = requests.session()
    search_url = 'http://{}/{}/{}/_search'.format(app.config['ES_HOST'], _es_index_device_door, _es_type_device_door)
    search_query = {'query': {'bool': {'must': [{'term': {'device_id': device_id}}]}}}
    response = rs.post(url=search_url, json=search_query, headers=_http_headers).json()

    if 'hits' not in response:
        app.logger.error('Elasticsearch down, response: ' + str(response))
        return None, {'message': 'internal server error'}, 500

    if response['hits']['total'] > 0:
        for hit in response['hits']['hits']:
            app.logger.info('get_door_from_device_id method completed')
            return hit['_source']['door_id'], 'device found', 200
    app.logger.info('No door found')
    return None, {"message": 'no door found'}, 404


def user_door_access(user_id, door_id):
    app.logger.info('user_door_access method called')
    rs = requests.session()
    search_url = 'http://{}/{}/{}/_search'.format(app.config['ES_HOST'], _es_index_user_door,
                                                  _es_type_user_door)
    search_query = {
        'query': {'bool': {'must': [{'term': {'door_id': door_id}}, {'term': {'user_id': user_id}}]}}}
    response = rs.post(url=search_url, json=search_query, headers=_http_headers).json()

    if 'hits' not in response:
        app.logger.error('Elasticsearch down, response: ' + str(response))
        return None, {'message': 'internal server error'}, 500

    if response['hits']['total'] > 0:
        app.logger.info('user_door_access method completed')
        return True, 'found', 200
    app.logger.info('No data found')
    return False, 'not found', 200


def enroll_user_log(user_id, door_id, minio_file_ref, face_matching_response, current_user, device_id, device_data = None):
    app.logger.info('enroll_user_log method called')
    rs = requests.session()
    data = {'user_id': user_id, 'door_id': door_id, 'minio_file_ref': minio_file_ref,
            'face_matching_response': face_matching_response,
            'device_id' : device_id,
            'created_by': current_user, 'updated_by': current_user,
            'created_at': int(time.time()), 'updated_at': int(time.time())}

    if device_data is not None and 'device_type' in device_data:
        if device_data['device_type'] == device_type_entry_door:
            data['event'] = entry
        elif device_data['device_type'] == device_type_exit_door:
            data['event'] = exit
        elif device_data['device_type'] == device_type_indoor:
            data['event'] = 'detected indoor'
        elif device_data['device_type'] == device_type_outdoor:
            data['event'] = 'detected outdoor'
        else :
            data['event'] = unknown

    else:
        data['event'] = unknown

    post_url = 'http://{}/{}/{}'.format(app.config['ES_HOST'], _es_index_access_log, _es_type_access_log)
    app.logger.debug('Insert data in elastic')
    response = rs.post(url=post_url, json=data, headers=_http_headers).json()
    app.logger.debug('Response: ' + str(response))
    app.logger.info('enroll_user_log method completed')


def enroll_user_log_warning(user_id, minio_file_ref, face_matching_response, current_user, device_id):
    app.logger.info('enroll_user_log_warning method called')
    rs = requests.session()
    data = {'user_id': user_id, 'minio_file_ref': minio_file_ref,
            'face_matching_response': face_matching_response,
            'device_id' : device_id,
            'warning_status' : 'unread',
            'event' : 'warning',
            'created_by': current_user, 'updated_by': current_user,
            'created_at': int(time.time()), 'updated_at': int(time.time())}

    post_url = 'http://{}/{}/{}'.format(app.config['ES_HOST'], _es_index_access_log, _es_type_access_log)
    app.logger.debug('Insert data in elastic')
    response = rs.post(url=post_url, json=data, headers=_http_headers).json()
    app.logger.debug('Response: ' + str(response))
    app.logger.info('enroll_user_log_warning method completed')


def face_matching_unknown(image64, user_id, door_id, current_user, device_id):
    app.logger.info('face_matching_unknown method called')
    t1 = time.time()
    fm_response = unknown
    curtime = int(time.time())
    file_name = 'unknown/' + str(curtime) + str(int(random()))
    upload_image(image64, file_name)
    pub_object.publish_face_match_unknown(door_id, file_name + ".jpg")
    enroll_user_log(user_id, door_id, file_name + ".jpg", fm_response, current_user, device_id)
    t2 = time.time()
    app.logger.info('face_matching_unknown Service Time Taken: ' + str(t2 - t1))
    app.logger.info('face_matching_unknown method completed')


def face_matching_authorized(image64, user_id, door_id, current_user, device_id, device_data):
    app.logger.info('face_matching_authorized method called')
    t1 = time.time()
    fm_response = found
    curtime = int(time.time())
    file_name = 'found/' + str(curtime) + str(int(random()))
    pub_object.publish_face_match_found(door_id, user_id, file_name)
    upload_image(image64, file_name)
    enroll_user_log(user_id, door_id, file_name + ".jpg", fm_response, current_user, device_id, device_data)
    t2 = time.time()
    app.logger.info('face_matching_authorized Service Time Taken: ' + str(t2 - t1))
    app.logger.info('face_matching_authorized method completed')


def face_matching_unauthorized(image64, user_id, door_id, current_user, device_id):
    t1 = time.time()
    app.logger.info('face_matching_unauthorized method called')
    fm_response = unauthorized
    curtime = int(time.time())
    file_name = 'found/' + str(curtime) + str(int(random()))

    pub_object.publish_face_match_unauthorized(door_id, user_id, file_name)
    upload_image(image64, file_name)
    enroll_user_log(user_id, door_id, file_name + ".jpg", fm_response, current_user, device_id)
    t2 = time.time()
    app.logger.info('face_matching_unauthorized Service Time Taken: ' + str(t2 - t1))
    app.logger.info('face_matching_unauthorized method completed')


def check_warning(device_id, device_data, user_data, image64, current_user):
    t1 = time.time()
    app.logger.info('check_warning method called')
    rs = requests.session()
    search_url = 'http://{}/{}/{}/_search'.format(app.config['ES_HOST'], _es_index_access_log,
                                                  _es_type_access_log)
    must = [{'term': {'user_id': user_data['id']}}]
    should = [{'match': {'event': entry}}, {'match': {'event': exit}}]
    search_query = {'query': {'bool': {'must': [{"bool":{"should" : should}}, must]}}}
    # search_query = {'query': {'bool': {'must': must}}}
    search_query['sort'] = [{'updated_at': {'order': 'desc'}}]
    response = rs.post(url=search_url, json=search_query, headers=_http_headers).json()

    if 'hits' not in response:
        app.logger.error('Elasticsearch down, response: ' + str(response))
        return {'message': 'internal server error'}, 500

    last_log = {}

    if response['hits']['total'] > 0:
        last_log = response['hits']['hits'][0]['_source']

    warning = True
    last_event = last_log.get('event', None)
    if device_data['device_type'] == device_type_indoor:
        if last_event == entry:
            warning = False

    if device_data['device_type'] == device_type_outdoor:
        if last_event == exit:
            warning = False

    if warning is False:
        app.logger.info('check_warning method completed')
        t2 = time.time()
        app.logger.info('check_warning Service Time Taken: ' + str(t2 - t1))
        return {'message': 'No warning found'}, 200

    fm_response = 'warning'
    curtime = int(time.time())
    file_name = 'warning/' + str(curtime) + str(int(random()))

    pub_object.publish_face_match_warning(device_id, user_data['id'], file_name)
    upload_image(image64, file_name)
    enroll_user_log_warning(user_data['id'], file_name + ".jpg", fm_response, current_user, device_id)
    app.logger.info('check_warning method completed')
    t2 = time.time()
    app.logger.info('check_warning Service Time Taken: ' + str(t2 - t1))
    return {'message': 'Warning found'}, 200


def get_door_list(user_id):
    app.logger.info('get_door_list method called')
    rs = requests.session()

    door_list = []

    app.logger.info('Search door information for the current user')
    query_json = {'query': {'bool': {'must': {'match': {'user_id': user_id}}}}}
    app.logger.debug('query_json: ' + str(json.dumps(query_json)))
    search_url = 'http://{}/{}/{}/_search'.format(app.config['ES_HOST'], _es_index_user_door,
                                                  _es_type_user_door)
    response = rs.post(url=search_url, json=query_json, headers=_http_headers).json()
    app.logger.debug('Response: ' + str(response))

    if 'hits' in response:
        for hit in response['hits']['hits']:
            door_data = hit['_source']
            door_list.append(door_data['door_id'])
    app.logger.info('get_door_list method completed')
    return door_list


def get_rect_width(rect):
    return abs(rect['end_x'] - rect['start_x'])


def get_rect_height(rect):
    return abs(rect['end_y'] - rect['start_y'])


def get_rect_area(rect):
    return get_rect_width(rect)*get_rect_height(rect)


def is_same_rect(rect1, rect2):
    t1 = time.time()
    app.logger.info('is_same_rect called')
    app.logger.debug('rect1: ' + str(json.dumps(rect1)))
    app.logger.debug('rect2: ' + str(json.dumps(rect2)))

    overlap_x = max(0, min(rect1['end_x'], rect2['end_x']) - max(rect1['start_x'], rect2['start_x']))
    overlap_y = max(0, min(rect1['end_y'], rect2['end_y']) - max(rect1['start_y'], rect2['start_y']))
    # app.logger.debug('overlap_x: ' + str(overlap_x))
    # app.logger.debug('overlap_y: ' + str(overlap_y))
    overlap_area = overlap_x * overlap_y
    rect1['area'] = get_rect_area(rect1)
    app.logger.debug('rect1 area: ' + str(rect1['area']))
    app.logger.debug('overlap_area: ' + str(overlap_area))
    app.logger.debug('percentage: ' + str((overlap_area/rect1['area'])*100.0))
    if overlap_area >= rect1['area'] * 0.4:
        app.logger.info('Found True')
        t2 = time.time()
        app.logger.info('is_same_rect Service Time Taken: ' + str(t2 - t1))
        return True
    t2 = time.time()
    app.logger.info('Found False')
    app.logger.info('is_same_rect Service Time Taken: ' + str(t2 - t1))
    return False


def rect_add_padding(rect, dx, dy):
    rect['start_x'] += dx
    rect['start_y'] += dy
    rect['end_x'] -= dx
    rect['end_y'] -= dy
    return rect


def get_image_rect(image_base64):
    app.logger.info('get_image_rect called')
    t1 = time.time()
    image = base64.b64decode(image_base64)
    im = image_cropper.bytes2PIL(image)
    width, height = im.size

    image_rect = {
        "end_x": width,
        "end_y": height,
        "start_x": 0,
        "start_y": 0
    }
    image_rect['width'] = get_rect_width(image_rect)
    image_rect['height'] = get_rect_height(image_rect)
    app.logger.debug('image_rect: ' + str(json.dumps(image_rect)))

    dx = (image_rect['width'] - image_rect['width'] / (1 + image_rect_factor * 2)) / 2
    dy = (image_rect['height'] - image_rect['height'] / (1 + image_rect_factor * 2)) / 2
    app.logger.debug('dx: ' + str(dx))
    app.logger.debug('dy: ' + str(dy))
    new_rect = rect_add_padding(image_rect, dx, dy)
    app.logger.debug('new rect: ' + str(json.dumps(new_rect)))
    app.logger.info('get_image_rect done')
    t2 = time.time()
    app.logger.info('Get_image_rect Service Time Taken: ' + str(t2 - t1))
    return new_rect


def generate_access_string_from_roles(user_role):
    role_names = user_role.split()
    app.logger.debug(f'Preparing method access rules for roles {role_names}')

    query = {'size': len(role_names), 'query': {'terms': {'role_id': role_names}}}

    search_url = 'http://{}/{}/{}/{}'.format(app.config['ES_HOST'], _es_role_index, _es_role_type, '_search')

    rs = requests.session()

    response = rs.post(url=search_url, json=query).json()
    if 'hits' in response:
        all_method_access = {}
        for hit in response['hits']['hits']:
            method_access = hit['_source'].get('method_access')
            for access in method_access:
                all_method_access[access['access_code']] = access
        return list(all_method_access.values())
    else:
        raise RuntimeError


@api.route('/<string:user_id>')
class User(Resource):

    @access_required(access='VIEW_USER CREATE_USER DELETE_USER UPDATE_USER SEARCH_USER')
    @api.doc('get user by id')
    def get(self, user_id):
        app.logger.info('Get user info api called')
        rs = requests.session()
        try:
            search_url = 'http://{}/{}/{}/_search'.format(app.config['ES_HOST'], _es_index, _es_type)
            search_query = {'query': {'bool': {'must': [{'term': {'_id': user_id}}]}}}
            response = rs.post(url=search_url, json=search_query, headers=_http_headers).json()

            if 'hits' not in response:
                return {'message': 'internal server error'}, 500
            if response['hits']['total'] > 0:
                es_data = response['hits']['hits'][0]['_source']
                es_data['id'] = response['hits']['hits'][0]['_id']
                es_data['door_list'] = get_door_list(es_data['id'])
                access_list = generate_access_string_from_roles(es_data.get('user_role'))
                es_data['user_access'] = ' '.join([item['access_code'] for item in access_list])
                app.logger.info('Get user info api completed')
                return es_data, 200
            else:
                app.logger.warning('no user found')
                return {"message": 'no user found'}, 200
            app.logger.error('Elasticsearch down, response: ' + str(response))
            return {'message': str(response)}, 500

        except Exception as e:
            app.logger.error('Elasticsearch down, response: ' + str(response))
            return {'message': str(e)}, 500

    @access_required(access='DELETE_USER CREATE_USER UPDATE_USER')
    @api.doc('update user by id')
    def put(self, user_id):
        app.logger.info("User update service called")
        ignore_fields = ['username', 'password', 'user_access']

        app.logger.info('Update user API called, id: ' + str(user_id))

        rs = requests.session()
        user_data = request.get_json()

        search_url = 'http://{}/{}/{}/{}'.format(app.config['ES_HOST'], _es_index, _es_type, user_id)
        response = rs.get(url=search_url, headers=_http_headers).json()
        if 'found' in response:
            if response['found']:
                user = response['_source']
                for key, value in user.items():
                    if key not in ignore_fields and key in user_data and user_data[key] != value:
                        user[key] = user_data[key]
                """
                try:
                    if 'user_role' in user_data:
                        access_list = self.__generate_access_string_from_roles(user_data.get('user_role'))
                        user['user_access'] = ' '.join([item['access_code'] for item in access_list])
                except RuntimeError as err:
                    app.logger.error('Elasticsearch down, response: ' + str(response))
                    return 'Elasticsearch error', 500
                """
                response = rs.put(url=search_url, json=user, headers=_http_headers).json()
                if 'result' in response:
                    app.logger.info("User update service completed")
                    return response['result'], 200
            return 'not found', 404
        app.logger.error('Elasticsearch down, response: ' + str(response))
        return response, 500

    @access_required(access='DELETE_USER')
    @api.doc('delete user by id')
    def delete(self, user_id):
        app.logger.info("User delete service called")
        rs = requests.session()
        search_url = 'http://{}/{}/{}/{}'.format(app.config['ES_HOST'], _es_index, _es_type, user_id)
        response = rs.delete(url=search_url, headers=_http_headers).json()
        if 'found' in response:
            app.logger.info("User delete service completed")
            return response['result'], 200
        app.logger.error('Elasticsearch down, response: ' + str(response))
        return response, 500


@api.route('/')
class CreateUser(Resource):

    @staticmethod
    def __validate_json(json_data):
        mandatory_fields = ['username', 'password', 'fullname', 'user_role', 'phone']
        for key, value in json_data.items():
            if key in mandatory_fields and not value:
                raise KeyError('Mandatory field missing')
        return json_data

    @access_required(access='DELETE_USER CREATE_USER')
    @api.doc('create new user')
    def post(self):
        app.logger.info('Create user API called')
        rs = requests.session()
        data = request.get_json()

        try:
            user_data = self.__validate_json(data)
            user_data['password'] = md5(user_data['password'].encode(encoding='utf-8')).hexdigest()
        except (IOError, KeyError):
            app.logger.warning('Bad request')
            return 'bad request', 400

        #if len(data['phone']) != 11 or data['phone'].startswith('01') is False:
        #    return {'message': 'phone number is invalid'}, 400

        search_url = 'http://{}/{}/{}/_search'.format(app.config['ES_HOST'], _es_index, _es_type)
        query_params = {'query': {'bool': {'must': [{'match': {'username': data['username']}}]}}}
        response = rs.post(url=search_url, json=query_params, headers=_http_headers).json()

        if 'hits' in response:
            if response['hits']['total'] >= 1:
                app.logger.warning('Username already exists')
                return 'username already exists', 200
        """
        try:
            access_list = self.__generate_access_string_from_roles(user_data.get('user_role'))
        except RuntimeError as err:
            app.logger.error('Elasticsearch down, response: ' + str(response))
            return 'Elasticsearch error', 500

        user_data['user_access'] = ' '.join([item['access_code'] for item in access_list])
        
        """

        # user_data['status'] = pending

        image_data = data.get('image_data', None)
        if 'image_data' in data:
            user_data.pop('image_data')
        post_url = 'http://{}/{}/{}'.format(app.config['ES_HOST'], _es_index, _es_type)
        response = rs.post(url=post_url, json=user_data, headers=_http_headers).json()

        if 'result' in response:
            if response['result'] == 'created' or response['result'] == 'updated':
                if image_data is not None:
                    store_image_v2(response['_id'], image_data, app.config['FM_HOST_USER'])
                    image_filename = response['_id'] + "_large"
                    upload_image(image_data, image_filename)
                app.logger.info("Created user service called")
                return response['_id'], 201
        app.logger.error('Elasticsearch down, response: ' + str(response))
        return response, 500


@api.route('/search', defaults={'page': 0})
@api.route('/search/<int:page>')
class SearchUser(Resource):

    @access_required(access='DELETE_USER CREATE_USER UPDATE_USER SEARCH_USER VIEW_USER')
    @api.doc('search users based on post parameters')
    def post(self, page=0):
        rs = requests.session()
        app.logger.info("User search service called")
        param = request.get_json()

        query_json = {'query': {'bool': {'must': []}}}

        for k in param:
            if k in keywords:
                query_json['query']['bool']['must'].append({'term': {k: param[k]}})
            else:
                query_json['query']['bool']['must'].append({'match': {k: param[k]}})

        query_json['from'] = page * _es_size
        query_json['size'] = _es_size
        search_url = 'http://{}/{}/{}/_search'.format(app.config['ES_HOST'], _es_index, _es_type)

        response = rs.post(url=search_url, json=query_json, headers=_http_headers).json()
        if 'hits' in response:
            data = []
            for rec in response['hits']['hits']:
                tdata = rec['_source']
                tdata['id'] = rec['_id']
                app.logger.info('Search booth information for the current user')
                query_json = {'query': {'bool': {'must': {'match': {'user_id': rec['_id']}}}}}
                app.logger.debug('query_json: ' + str(json.dumps(query_json)))
                search_url = 'http://{}/{}/{}/_search'.format(app.config['ES_HOST'], _es_index_booth, _es_type_booth)
                response = rs.post(url=search_url, json=query_json, headers=_http_headers).json()
                app.logger.debug('Response: ' + str(response))
                access_list = generate_access_string_from_roles(tdata.get('user_role'))
                tdata['user_access'] = ' '.join([item['access_code'] for item in access_list])
                tdata['appointment_status'] = False

                if 'hits' in response:
                    for hit in response['hits']['hits']:
                        booth_data = hit['_source']
                        tdata['booth_id'] = hit['_id']
                        for k in booth_data:
                            tdata[k] = booth_data[k]
                        cur_time = int(time.time())
                        if cur_time >= int(booth_data['start_time']) and cur_time <= int(booth_data['end_time']):
                            tdata['appointment_status'] = True
                data.append(tdata)
            app.logger.info("User search service completed")
            return data, 200
        app.logger.error('Elasticsearch down, response: ' + str(response))
        return {'message': 'internal server error'}, 500


@api.route('/dtsearch')
@api.route('/<string:role>/dtsearch')
class SearchUserDT(Resource):

    @access_required(access='DELETE_USER CREATE_USER UPDATE_USER SEARCH_USER VIEW_USER')
    @api.doc('search users based on query parameters')
    def get(self, role = None):
        app.logger.info('User dt search service called')
        param = request.args.to_dict()
        for key in param:
            param[key] = param[key].replace('"', '')

        app.logger.debug('params: ' + str(param))

        pageIndex = 0
        pageSize = _es_size

        if 'pageIndex' in param:
            pageIndex = int(param['pageIndex'])

        if 'pageSize' in param:
            pageSize = int(param['pageSize'])

        should = []
        search_fields = ['fullname', 'username', 'user_role', 'user_access', 'action', 'user_type']
        if 'filter' in param and param['filter']:
            for k in search_fields:
                should.append({'term': {k: param['filter']}})
            should.append({'match': {'event': param['filter']}})

        if role is None:
            query = {'bool': {'must': []}}
        else:
            query = {'bool': {'must': [{'match': {'role': role}}]}}

        if len(should) != 0:
            query['bool']['must'].append({'bool': {'should': should}})

        query_json = {'query': query, 'from': pageIndex * pageSize, 'size': pageSize}

        #if 'sortActive' in param:
        #    query_json['sort'] = [{param['sortActive']: {'order': param['sortOrder']}}]

        app.logger.debug('ES Query: ' + str(json.dumps(query_json)))

        search_url = 'http://{}/{}/{}/_search'.format(app.config['ES_HOST'], _es_index, _es_type)
        response = requests.session().post(url=search_url, json=query_json, headers=_http_headers).json()


        if 'hits' in response:
            data = []
            for hit in response['hits']['hits']:
                user = hit['_source']
                user['id'] = hit['_id']
                access_list = generate_access_string_from_roles(user.get('user_role'))
                user['user_access'] = ' '.join([item['access_code'] for item in access_list])
                data.append(user)
            return_data = {
                'user_list': data,
                'count': response['hits']['total']
            }
            app.logger.info('User dt search service completed')
            return return_data, 200
            # return data, 200
        app.logger.error('Elasticsearch down, response: ' + str(response))
        return {'message': 'internal server error'}, 500


@api.route('/changepass/<string:user_id>')
class ChangePassword(Resource):

    @access_required(access='UPDATE_USER')
    @api.doc('update user password')
    def put(self, user_id):
        app.logger.info(f'Attempting to update password for user {user_id}')
        rs = requests.session()

        fields = ['old_password', 'new_password']
        user_data = request.get_json()
        for field in fields:
            if user_data.get(field, None) is None:
                return 'bad request', 400

        old_pass = md5(user_data['old_password'].encode(encoding='utf-8')).hexdigest()
        new_pass = md5(user_data['new_password'].encode(encoding='utf-8')).hexdigest()

        search_url = 'http://{}/{}/{}/{}'.format(app.config['ES_HOST'], _es_index, _es_type, user_id)
        response = rs.get(url=search_url).json()

        if 'found' in response:
            if response['found']:
                data = response['_source']
                if data['password'] != old_pass:
                    return 'Wrong password', 409
                data['password'] = new_pass
                upd_response = rs.put(url=search_url, json=data)
                if upd_response.ok:
                    app.logger.info('Password has been updated')
                    return 'updated', 200
            else:
                app.logger.debug('User does not exist')
                return 'user not found', 404
        app.logger.error('Elasticsearch down, response: ' + str(response))
        return 'internal server error', 500


@api.route('/setpass/<string:user_id>')
class SetPassword(Resource):

    @access_required(access='UPDATE_USER')
    @api.doc('update user password')
    def put(self, user_id):
        app.logger.info(f'Attempting to update password for user {user_id}')
        rs = requests.session()

        fields = ['new_password']
        user_data = request.get_json()
        for field in fields:
            if user_data.get(field, None) is None:
                return 'bad request', 400

        new_pass = md5(user_data['new_password'].encode(encoding='utf-8')).hexdigest()

        search_url = 'http://{}/{}/{}/{}'.format(app.config['ES_HOST'], _es_index, _es_type, user_id)
        response = rs.get(url=search_url).json()

        if 'found' in response:
            if response['found']:
                data = response['_source']
                data['password'] = new_pass
                upd_response = rs.put(url=search_url, json=data)
                if upd_response.ok:
                    app.logger.info('Password has been updated')
                    return 'updated', 200
            else:
                app.logger.debug('User does not exist')
                return 'user not found', 404
        app.logger.error('Elasticsearch down, response: ' + str(response))
        return 'internal server error', 500


@api.route('/access')
class MatchingAccess(Resource):

    @access_required(access='CREATE_USER DELETE_USER UPDATE_USER SEARCH_USER VIEW_USER SEARCH_FACE')
    @api.doc('Face matching in tigerit server')
    def post(self):
        app.logger.info("User access service called")
        t1 = time.time()
        current_user = get_jwt_identity().get('id')
        rs = requests.session()
        data = request.get_json()
        try:
            for mfield in match_mandatory_fields:
                if mfield not in data:
                    return {'message': 'Required fields not given'}, 400

            image_data = data['image_data']
            local_frs_threshold = data['threshold']
            ip_address = data['ip_address']
            app.logger.debug("Threshold is " + str(local_frs_threshold))

            device_data, device_id, msg, response_code = get_device_from_ip_address(ip_address)

            if device_id is None:
                return msg, response_code

            door_id, msg, response_code = get_door_from_device_id(device_id)

            if door_id is None:
                return msg, response_code

            match_response = match_image_v2(image_data, app.config['FM_HOST_USER'])
            face_data = None

            return_data = {
                'result': [],
                'match_count': 0
            }

            if len(match_response) > 0:
                face_data = match_response[0]

            if face_data is None or face_data['probability'] < local_frs_threshold:
                app.logger.info('No match found')
                face_matching_unknown(image_data, unknown, door_id, current_user, device_id)
                return_data['access_status'] = unknown
                return return_data

            app.logger.debug('Found face: ' + str(face_data))

            rect_1 = face_data['bbox']
            rect_2 = get_image_rect(image_data)

            if is_same_rect(rect_2, rect_1) is False:
                app.logger.info('No match found, overlapped image is invalid')
                face_matching_unknown(image_data, unknown, door_id, current_user, device_id)
                return_data['access_status'] = unknown
                return return_data

            search_url = 'http://{}/{}/{}/{}'.format(app.config['ES_HOST'], _es_index, _es_type, face_data['name'])
            response = rs.get(url=search_url, headers=_http_headers).json()

            app.logger.debug(response)

            if 'found' not in response:
                app.logger.error('Elasticsearch down, response: ' + str(response))
                return {'message': 'internal server error'}, 500


            if response['found']:
                app.logger.debug(response['found'])
                data = response['_source']
                data['id'] = response['_id']

                # Check for indoor and outdoor camera:
                if device_data['device_type'] == device_type_indoor or device_data['device_type'] == device_type_outdoor:
                    check_warning(device_id, device_data, data, image_data, current_user)

                if 'status' in data and data['status'] == pending:
                    app.logger.warning("User status pending")
                    return {'message': 'status pending'}, 404

                face_data['minio_url'] = minio_client.connection.presigned_get_object(app.config['MINIO_BUCKETS'][0],
                                                                                      data['id'] + '_large.jpg',
                                                                                      expires=timedelta(seconds=30))
                face_data['guest_data'] = data

                return_data['name'] = face_data['name']
                return_data['probability'] = face_data['probability']
                return_data['match_count'] = 1
                return_data['result'].append(face_data)

                access, msg, response_code = user_door_access(data['id'], door_id)
                if access is None:
                    return msg, response_code

                if access:
                    face_matching_authorized(image_data, data['id'], door_id, current_user, device_id, device_data)
                    return_data['access_status'] = authorized
                    t2 = time.time()
                    app.logger.info('Access Service Time Taken: ' + str(t2-t1))
                    return return_data

                face_matching_unauthorized(image_data, data['id'], door_id, current_user, device_id)
                return_data['access_status'] = unauthorized
                t3 = time.time()
                app.logger.info('Access Service Time Taken: ' + str(t3 - t1))
                return return_data

            face_matching_unknown(image_data, unknown, door_id, current_user, device_id)
            app.logger.info("Face matching service done")
            return_data['access_status'] = unknown
            app.logger.info("User access service completed")
            t4 = time.time()
            app.logger.info('Access Service Time Taken: ' + str(t4 - t1))
            return return_data

        except Exception as e:
            app.logger.error('Exception occurred: ' + str(e))
            return {'message': str(e)}, 500


"""
@api.route('/door')
class AddDoorToUser(Resource):

    @access_required(access='CREATE_USER DELETE_USER UPDATE_USER')
    @api.doc('Add new door access for user')
    def post(self):
        app.logger.info('User add door service called')
        current_user = get_jwt_identity().get('id')
        rs = requests.session()
        data = request.get_json()
        if 'user_id' not in data:
            return {'message': 'user_id not given'}, 400
        if 'door_list' not in data:
            return {'message': 'door_list not given'}, 400

        door_id_list = []

        for door_id in data['door_list']:
            door_data = {
                'door_id': door_id,
                'user_id': data['user_id']
            }
            door_data['created_by'] = current_user
            door_data['created_at'] = int(time.time())
            door_data['updated_by'] = current_user
            door_data['updated_at'] = int(time.time())
            post_url = 'http://{}/{}/{}'.format(app.config['ES_HOST'], _es_index_user_door, _es_type_user_door)
            response = rs.post(url=post_url, json=door_data, headers=_http_headers).json()
            if 'created' not in response:
                app.logger.error('Elasticsearch down, response: ' + str(response))
                return response, 500
            if response['created']:
                door_id_list.append(response['_id'])

        app.logger.info('User add door service completed')
        return door_id_list, 200
"""

@api.route('/door')
class AddDoorToUser(Resource):

    @access_required(access='CREATE_USER DELETE_USER UPDATE_USER')
    @api.doc('Add new door access for user')
    def post(self):
        app.logger.info('User add door service called')
        current_user = get_jwt_identity().get('id')
        rs = requests.session()
        data = request.get_json()
        if 'user_id' not in data:
            return {'message': 'user_id not given'}, 400
        if 'door_list' not in data:
            return {'message': 'door_list not given'}, 400

        delete_query = {'query': {'bool': {'must': [{'term': {'user_id': data['user_id']}}]}}}
        delete_url = 'http://{}/{}/{}/_delete_by_query'.format(app.config['ES_HOST'], _es_index_user_door, _es_type_user_door)
        app.logger.debug('Elasticsearch query : ' + str(delete_query))
        response = rs.post(url=delete_url, json=delete_query, headers=_http_headers).json()
        app.logger.debug('Elasticsearch response : ' + str(response))

        door_id_list = []

        for door_id in data['door_list']:
            door_data = {
                'door_id': door_id,
                'user_id': data['user_id']
            }
            door_data['created_by'] = current_user
            door_data['created_at'] = int(time.time())
            door_data['updated_by'] = current_user
            door_data['updated_at'] = int(time.time())
            post_url = 'http://{}/{}/{}'.format(app.config['ES_HOST'], _es_index_user_door, _es_type_user_door)
            response = rs.post(url=post_url, json=door_data, headers=_http_headers).json()
            if 'created' not in response:
                app.logger.error('Elasticsearch down, response: ' + str(response))
                return response, 500
            if response['created']:
                door_id_list.append(response['_id'])

        app.logger.info('User add door service completed')
        return door_id_list, 200

@api.route('/door/<string:user_id>')
class DeleteDoorForUser(Resource):

    @access_required(access='CREATE_USER DELETE_USER UPDATE_USER')
    @api.doc('Delete door access for user')
    def delete(self, user_id):
        app.logger.info('User delete door service called')
        rs = requests.session()

        search_url = 'http://{}/{}/{}/_search'.format(app.config['ES_HOST'], _es_index_user_door, _es_type_user_door)
        query_json = {'query': {'bool': {'must': [{'term': {'user_id': user_id}}]}}}
        query_json['size'] = _es_size
        response = rs.post(url=search_url, json=query_json, headers=_http_headers).json()

        if 'hits' in response:
            id_list = []
            for rec in response['hits']['hits']:
                doc_id = rec['_id']
                id_list.append(doc_id)
                delete_url = 'http://{}/{}/{}/{}'.format(app.config['ES_HOST'], _es_index_user_door, _es_type_user_door, doc_id)
                response = rs.delete(url=delete_url, headers=_http_headers).json()
                if 'result' not in response:
                    app.logger.error('Elasticsearch down, response: ' + str(response))
                    return 'Internal Server Error', 500

            app.logger.info('User delete door service completed')
            return id_list

        app.logger.error('Elasticsearch down, response: ' + str(response))
        return response, 500


@api.route('/suggest/<string:prefix>')
class UserSuggester(Resource):

    @staticmethod
    def _transform(v):
        return v['text']

    @access_required(access='CREATE_USER DELETE_USER UPDATE_USER SEARCH_USER VIEW_USER')
    def get(self, prefix):
        app.logger.info('User suggest service called')
        data = {'_source': _es_src_filter, 'suggest': {'name_suggest': {'prefix': prefix,
                                                                        'completion': {'field': 'suggest',
                                                                                       'size': _es_size
                                                                                       }}}}
        search_url = 'http://{}/{}/{}/_search'.format(app.config['ES_HOST'], _es_index, _es_type)
        response = requests.session().post(url=search_url.format(app.config['ES_HOST'], _es_index, _es_type),
                                           json=data,
                                           headers=_http_headers).json()

        if 'suggest' in response:
            app.logger.info('User suggest service completed')
            return sorted(set([self._transform(v) for v in response['suggest']['name_suggest'][0]['options']])), 200
        app.logger.error('Elasticsearch down, response: ' + str(response))
        return 'internal server error', 500


@api.route('/door/search', defaults={'page': 0})
@api.route('/door/search/<int:page>')
class SearchDoorsForUsers(Resource):

    @api.doc('Custom search using post request')
    def post(self, page=None):
        app.logger.info('User with door search service called')

        if not page:
            page = 0

        rs = requests.session()

        try:
            data = request.get_json()
            must = []
            search_url = 'http://{}/{}/{}/_search'.format(app.config['ES_HOST'], _es_index, _es_type)
            for k in data:
                if k == 'id':
                    must.append({'term': {'_id': data[k]}})
                else:
                    must.append({'match': {k: data[k]}})

            query = {'bool': {'must': must}}
            if len(must) == 0:
                query = {'match_all': {}}

            search_query = {'size': _es_size + 1, 'from': page * _es_size, 'query': query}
            response = rs.post(url=search_url, json=search_query, headers=_http_headers).json()

            user_list = []
            if 'hits' in response:
                app.logger.info('Found list of users from ES')
                for rec in response['hits']['hits']:
                    emp_data = rec['_source']
                    emp_data['id'] = rec['_id']
                    emp_data['door_list'] = get_door_list(rec['_id'])
                    user_list.append(emp_data)

                app.logger.info('User with door search service completed')
                return {'user_list': user_list}, 200
            app.logger.error('Elasticsearch down, response: ' + str(response))
            return response, 500

        except Exception as e:
            app.logger.error('Exception occurred: ' + str(e))
            return str(e), 500


@api.route('/door/dtsearch')
class DTSearchDoorForUsers(Resource):

    @jwt_required
    @api.doc('search users based on query parameters')
    def get(self):
        app.logger.info('User door dt search called')
        rs = requests.session()
        param = request.args.to_dict()
        for key in param:
            param[key] = param[key].replace('"', '')

        app.logger.debug('params: ' + str(param))

        pageIndex = 0
        pageSize = _es_size

        if 'pageIndex' in param:
            pageIndex = int(param['pageIndex'])

        if 'pageSize' in param:
            pageSize = int(param['pageSize'])

        should = []
        search_fields = ['department', 'designation', 'email', 'user_id', 'fullname', 'phone', 'internal_id', 'status']
        if 'filter' in param and param['filter']:
            for field in search_fields:
                should.append({'match': {field: param['filter']}})

        query = {'bool': {'should': should}}

        if len(should) == 0:
            query = {'match_all': {}}

        query_json = {'query': query, 'from': pageIndex * pageSize, 'size': pageSize}

        # if 'sortActive' in param:
        #    query_json['sort'] = [{param['sortActive']: {'order': param['sortOrder']}}]

        app.logger.debug('ES Query: ' + str(json.dumps(query_json)))

        search_url = 'http://{}/{}/{}/_search'.format(app.config['ES_HOST'], _es_index, _es_type)
        response = rs.post(url=search_url, json=query_json, headers=_http_headers).json()

        if 'hits' in response:
            data = []
            for hit in response['hits']['hits']:
                user = hit['_source']
                user['id'] = hit['_id']
                user['door_list'] = get_door_list(hit['_id'])
                data.append(user)
            return_data = {
                'user_list': data,
                'count': response['hits']['total']
            }
            app.logger.info('User door dt search completed')
            return return_data, 200
        app.logger.error('Elasticsearch down, response: ' + str(response))
        return {'message': 'internal server error'}, 500


@api.route('/log/search', defaults={'page': 0})
@api.route('/log/search/<int:page>')
class SearchLogForUsers(Resource):

    @api.doc('Custom search using post request')
    def post(self, page=None):
        app.logger.info('User Log search service called')

        if not page:
            page = 0

        rs = requests.session()

        try:
            data = request.get_json()
            must = []
            search_url = 'http://{}/{}/{}/_search'.format(app.config['ES_HOST'], _es_index_access_log, _es_type_access_log)

            term_list = ['device_id', 'door_id', 'user_id']

            for k in data:
                if k == 'id':
                    must.append({'term': {'_id': data[k]}})
                elif k in term_list:
                    must.append({'term': {k: data[k]}})
                else:
                    must.append({'match': {k: data[k]}})

            query = {'bool': {'must': must}}
            if len(must) == 0:
                query = {'match_all': {}}

            search_query = {'size': _es_size + 1, 'from': page * _es_size, 'query': query}
            app.logger.debug('ES Query: ' + str(search_query))
            response = rs.post(url=search_url, json=search_query, headers=_http_headers).json()
            app.logger.debug('ES Response: ' + str(response))

            log_list = []
            if 'hits' in response:
                app.logger.info('Found list of user logs from ES')
                for rec in response['hits']['hits']:
                    log_data = rec['_source']
                    log_data['id'] = rec['_id']

                    if 'door_id' in log_data:
                        door_details = get_door_details(log_data['door_id'])
                        log_data['door_name'] = door_details.get('door_name', None)
                        log_data['floor_id'] = door_details.get('floor_id', None)
                        log_data['room_id'] = door_details.get('room_id', None)

                    if 'user_id' in log_data:
                        door_details = get_user_details(log_data['user_id'])
                        log_data['user_name'] = door_details.get('fullname', None)

                    log_list.append(log_data)

                return_data = {
                    'log_list': log_list,
                    'count': response['hits']['total']
                }
                app.logger.info('User log search service completed')
                return return_data, 200
            app.logger.error('Elasticsearch down, response: ' + str(response))
            return response, 500

        except Exception as e:
            app.logger.error('Exception occurred: ' + str(e))
            return str(e), 500


@api.route('/log/dtsearch')
class UserAcessLogDTSearch(Resource):

    @jwt_required
    @api.doc('search user log based on query parameters')
    def get(self):
        app.logger.info('User log dt search called')
        param = request.args.to_dict()
        for key in param:
            param[key] = param[key].replace('"', '')

        app.logger.debug('params: ' + str(param))

        pageIndex = 0
        pageSize = _es_size

        if 'pageIndex' in param:
            pageIndex = int(param['pageIndex'])

        if 'pageSize' in param:
            pageSize = int(param['pageSize'])

        should = []
        search_fields = ['device_id', 'door_id', 'user_id']
        if 'filter' in param and param['filter']:
            for k in search_fields:
                should.append({'term': {k: param['filter']}})
            should.append({'match': {'event': param['filter']}})

        query = {'bool': {'should': should}}

        if len(should) == 0:
            query = {'match_all': {}}

        query_json = {'query': query, 'from': pageIndex * pageSize, 'size': pageSize}

        # if 'sortActive' in param:
        #    query_json['sort'] = [{param['sortActive']: {'order': param['sortOrder']}}]

        app.logger.debug('ES Query: ' + str(json.dumps(query_json)))

        search_url = 'http://{}/{}/{}/_search'.format(app.config['ES_HOST'], _es_index_access_log, _es_type_access_log)
        response = requests.session().post(url=search_url, json=query_json, headers=_http_headers).json()

        log_list = []
        if 'hits' in response:
            app.logger.info('Found list of user logs from ES')
            for rec in response['hits']['hits']:
                log_data = rec['_source']
                log_data['id'] = rec['_id']

                if 'door_id' in log_data:
                    door_details = get_door_details(log_data['door_id'])
                    log_data['door_name'] = door_details.get('door_name', None)
                    log_data['floor_id'] = door_details.get('floor_id', None)
                    log_data['room_id'] = door_details.get('room_id', None)

                if 'user_id' in log_data:
                    door_details = get_user_details(log_data['user_id'])
                    log_data['user_name'] = door_details.get('fullname', None)

                log_list.append(log_data)

            return_data = {
                'log_list': log_list,
                'count': response['hits']['total']
            }
            app.logger.info('User log dt search completed')
            return return_data, 200
        app.logger.error('Elasticsearch down, response: ' + str(response))
        return response, 500


@api.route('/log/warning/dtsearch')
class UserWarningLog(Resource):

    @jwt_required
    @api.doc('search user warning log based on query parameters')
    def get(self):
        app.logger.info('User log warning dt search called')
        param = request.args.to_dict()
        for key in param:
            param[key] = param[key].replace('"', '')

        app.logger.debug('params: ' + str(param))

        pageIndex = 0
        pageSize = _es_size

        if 'pageIndex' in param:
            pageIndex = int(param['pageIndex'])

        if 'pageSize' in param:
            pageSize = int(param['pageSize'])

        should = []
        search_fields = ['device_id', 'door_id', 'user_id']
        if 'filter' in param and param['filter']:
            for k in search_fields:
                should.append({'term': {k: param['filter']}})
            should.append({'match': {'event': param['filter']}})

        query = {'bool': {'must': [{'match': {'face_matching_response': 'warning'}}]}}

        if len(should) != 0:
            query['bool']['must'].append({'bool': {'should': should}})

        query_json = {'query': query, 'from': pageIndex * pageSize, 'size': pageSize}

        # if 'sortActive' in param:
        #    query_json['sort'] = [{param['sortActive']: {'order': param['sortOrder']}}]

        app.logger.debug('ES Query: ' + str(json.dumps(query_json)))

        search_url = 'http://{}/{}/{}/_search'.format(app.config['ES_HOST'], _es_index_access_log, _es_type_access_log)
        response = requests.session().post(url=search_url, json=query_json, headers=_http_headers).json()

        log_list = []
        if 'hits' in response:
            app.logger.info('Found list of user warning logs from ES')
            for rec in response['hits']['hits']:
                log_data = rec['_source']
                log_data['id'] = rec['_id']

                if 'door_id' in log_data:
                    door_details = get_door_details(log_data['door_id'])
                    log_data['door_name'] = door_details.get('door_name', None)
                    log_data['floor_id'] = door_details.get('floor_id', None)
                    log_data['room_id'] = door_details.get('room_id', None)

                if 'user_id' in log_data:
                    door_details = get_user_details(log_data['user_id'])
                    log_data['user_name'] = door_details.get('fullname', None)

                log_list.append(log_data)

            return_data = {
                'log_list': log_list,
                'count': response['hits']['total']
            }
            app.logger.info('User log warning dt search service completed')
            return return_data, 200
        app.logger.error('Elasticsearch down, response: ' + str(response))
        return response, 500


@api.route('/log/update/<string:log_id>')
class UserLogUpdate(Resource):

    @jwt_required
    @api.doc('search user warning log based on query parameters')
    def put(self, log_id):
        app.logger.info('User log update called')
        rs = requests.session()
        data = request.get_json()
        search_url = 'http://{}/{}/{}/{}'.format(app.config['ES_HOST'], _es_index_access_log, _es_type_access_log, log_id)
        response = rs.get(url=search_url, headers=_http_headers).json()

        if 'found' in response:
            if response['found']:
                es_data = response['_source']
                for k in data:
                    es_data[k] = data[k]
                response = rs.put(url=search_url, json=es_data, headers=_http_headers).json()
                app.logger.info('User log update completed')
                return response['result'], 200
            app.logger.warning('User log not found')
            return {'found': response['found']}, 404
        app.logger.error('Elasticsearch down, response: ' + str(response))
        return response, 500
