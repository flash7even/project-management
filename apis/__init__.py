from datetime import timedelta
from flask import Blueprint
from flask_restplus import Api
from flask import Flask
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from apis.flask_minio import minio_client
from config import Config, instances
from .flask_minio import minio_client
from .flask_mqtt import mqtt_client
from apis.flask_redis import redis_store

from .attendance_controller import api as attendance_ns
from .guest_controller import api as guest_ns
from .verification_controller import api as verification_ns
from .auth_controller import api as auth_ns
from .user_controller import api as user_ns
from .door_controller import api as door_ns
from .device_controller import api as device_ns
from .queue_controller import api as queue_ns
from .campaign_controller import api as camp_ns
from .user_role_controller import api as role_ns
from .method_access_controller import api as access_ns
blueprint = Blueprint('api', Config.APPNAME, url_prefix='/tardyapi')

api = Api(blueprint,
          title=Config.APPNAME,
          version=Config.VERSION,
          description='RESTful API for Minio Applications')

api.add_namespace(attendance_ns, path='/attendance')
api.add_namespace(guest_ns, path='/guest')
api.add_namespace(verification_ns, path='/verification')
api.add_namespace(auth_ns, path='/auth')
api.add_namespace(user_ns, path='/user')
api.add_namespace(door_ns, path='/door')
api.add_namespace(device_ns, path='/device')
api.add_namespace(queue_ns, path='/booth')
api.add_namespace(camp_ns, path='/camp')
api.add_namespace(role_ns, path='/role')
api.add_namespace(access_ns, path='/access')


def create_app(instance_name):
    app = Flask(__name__)
    app.config['PROPAGATE_EXCEPTIONS'] = True
    print('ENVIRONMENT NAME: ', instance_name)
    app.config.from_object(instances[instance_name])
    app.config.from_pyfile(f'{Config.BASEDIR}/minio-{instance_name}.cfg', silent=True)
    app.config.from_pyfile(f'{Config.BASEDIR}/elastic-{instance_name}.cfg', silent=True)
    app.config.from_pyfile(f'{Config.BASEDIR}/redis-{instance_name}.cfg', silent=True)
    app.config.from_pyfile(f'{Config.BASEDIR}/mqtt-{instance_name}.cfg', silent=True)
    app.config.from_pyfile(f'{Config.BASEDIR}/facematching-{instance_name}.cfg', silent=True)
    app.config.from_pyfile(f'{Config.BASEDIR}/jwt-{instance_name}.cfg', silent=True)
    minio_client.init_app(app)
    redis_store.init_app(app)
    mqtt_client.init_app(app)
    CORS(app)

    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=app.config['JWT_ACCESS_TOKEN_EXPIRES_MINUTES'])
    app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(minutes=app.config['JWT_REFRESH_TOKEN_EXPIRES_MINUTES'])

    jwt = JWTManager()

    @jwt.token_in_blacklist_loader
    def check_if_token_is_revoked(decrypted_token):
        jti = decrypted_token['jti']
        jti = redis_store.redis_prefix_jwt_token + jti
        if redis_store.connection.exists(jti):
            return True
        return False

    @jwt.user_claims_loader
    def add_claims_to_access_token(identity):
        return {'role': identity['user_role'], 'methods': identity['user_access']}

    jwt.init_app(app)
    app.register_blueprint(blueprint)

    return app