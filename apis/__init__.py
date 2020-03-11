from datetime import timedelta
from flask import Blueprint
from flask_restplus import Api
from flask import Flask
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from config import Config, instances

from .auth_controller import api as auth_ns
from .user_controller import api as user_ns
from .user_role_controller import api as role_ns
from .method_access_controller import api as access_ns
from .project_controller import api as project_ns
from .transaction_controller import api as transaction_ns
from .payment_method_controller import api as pmethod_ns
from .bill_controller import api as bill_ns
blueprint = Blueprint('api', Config.APPNAME, url_prefix='/api')

api = Api(blueprint,
          title=Config.APPNAME,
          version=Config.VERSION,
          description='RESTful API for Minio Applications')

api.add_namespace(auth_ns, path='/auth')
api.add_namespace(user_ns, path='/user')
api.add_namespace(role_ns, path='/role')
api.add_namespace(access_ns, path='/access')
api.add_namespace(project_ns, path='/project')
api.add_namespace(transaction_ns, path='/transaction')
api.add_namespace(bill_ns, path='/bill')
api.add_namespace(pmethod_ns, path='/payment/method')


def create_app(instance_name):
    app = Flask(__name__)
    app.config['PROPAGATE_EXCEPTIONS'] = True
    print('ENVIRONMENT NAME: ', instance_name)
    app.config.from_object(instances[instance_name])
    app.config.from_pyfile(f'{Config.BASEDIR}/elastic-{instance_name}.cfg', silent=True)
    app.config.from_pyfile(f'{Config.BASEDIR}/jwt-{instance_name}.cfg', silent=True)
    CORS(app)

    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=app.config['JWT_ACCESS_TOKEN_EXPIRES_MINUTES'])
    app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(minutes=app.config['JWT_REFRESH_TOKEN_EXPIRES_MINUTES'])

    jwt = JWTManager()

    @jwt.token_in_blacklist_loader
    def check_if_token_is_revoked(decrypted_token):
        return False

    @jwt.user_claims_loader
    def add_claims_to_access_token(identity):
        return {'role': identity['user_role'], 'methods': identity['user_access']}

    jwt.init_app(app)
    app.register_blueprint(blueprint)

    return app