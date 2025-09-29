import logging
import itertools
import os
import threading
import time
from flask import Blueprint, Flask, jsonify, request, send_file, send_from_directory
from flask_cors import CORS

try:
    from flask_rich import RichApplication
except ImportError:
    RichApplication = None

try:
    from flask_basicauth import BasicAuth
except ImportError:
    BasicAuth = None

try:
    from donpapi.lib.database import Database
except ImportError:
    # Fallback if donpapi is not available
    class Database:
        def __init__(self):
            pass

class NetworkServer:
    """Network server for data transmission"""
    
    def __init__(self):
        self.app = None
        self.host = '127.0.0.1'
        self.port = 8080
        self.ssl_enabled = False
        self.cert_file = None
        self.key_file = None
        self.running = False
        self.server_thread = None
    
    def configure(self, host='127.0.0.1', port=8080, ssl_enabled=False, cert_file=None, key_file=None):
        """Configure server settings"""
        self.host = host
        self.port = port
        self.ssl_enabled = ssl_enabled
        self.cert_file = cert_file
        self.key_file = key_file
        
        # Initialize Flask app
        self.app = Flask(__name__)
        CORS(self.app)
        
        # Add routes
        self._add_routes()
    
    def _add_routes(self):
        """Add server routes"""
        
        @self.app.route('/api/data', methods=['POST'])
        def handle_data():
            """Handle data transmission"""
            try:
                data = request.json
                # Process data
                return {'status': 'success', 'data': data}
            except Exception as e:
                return {'status': 'error', 'message': str(e)}, 500
        
        @self.app.route('/api/status', methods=['GET'])
        def get_status():
            """Get server status"""
            return {
                'status': 'running',
                'uptime': self.get_uptime(),
                'host': self.host,
                'port': self.port
            }
        
        @self.app.route('/api/health', methods=['GET'])
        def health_check():
            """Health check endpoint"""
            return {'status': 'healthy'}
    
    def start(self):
        """Start the server"""
        if self.app is None:
            self.configure()
        
        def run_server():
            try:
                if self.ssl_enabled and self.cert_file and self.key_file:
                    self.app.run(
                        host=self.host,
                        port=self.port,
                        ssl_context=(self.cert_file, self.key_file),
                        debug=False,
                        threaded=True
                    )
                else:
                    self.app.run(
                        host=self.host,
                        port=self.port,
                        debug=False,
                        threaded=True
                    )
            except Exception as e:
                print(f"Server error: {e}")
        
        self.server_thread = threading.Thread(target=run_server, daemon=True)
        self.server_thread.start()
        self.running = True
        self.start_time = time.time()
    
    def stop(self):
        """Stop the server"""
        self.running = False
        if self.server_thread:
            self.server_thread.join(timeout=5)
    
    def get_uptime(self):
        """Get server uptime"""
        if hasattr(self, 'start_time'):
            return time.time() - self.start_time
        return 0


class RichLoggingConfig:
    RICH_LOGGING = True

def generate_error_message(msg:str, error_code:int=404):
    return {
        "error":error_code,
        "message":msg
    }, error_code

def start_gui(options, db_engine, db: Database) -> None:
    app = Flask(__name__)  # noqa: F811

    gui_path = 'res/gui'

    if options.basic_auth:
        username, password = options.basic_auth.split(":",1)
        app.config['BASIC_AUTH_USERNAME'] = username
        app.config['BASIC_AUTH_PASSWORD'] = password
        app.config['BASIC_AUTH_FORCE'] = password
        _ = BasicAuth(app)
        
    _ = RichApplication(app)
    
    # Allow CORS requests from Angular if it's running in develop mode
    CORS(app, origins=['http://127.0.0.1:5173', 'http://localhost:5173'])

    # Handle logging
    rich_handler = [
        handler for handler in logging.getLogger().handlers
        ][0]
    logging.getLogger().removeHandler(rich_handler)

    donpapi_file_logger = logging.getLogger("donpapi").handlers[0]
    app.logger.addHandler(donpapi_file_logger)
    # Support for Werkzeug's logger
    logging.getLogger("werkzeug").addHandler(donpapi_file_logger)

    ssl_context = None
    if options.ssl:
        ssl_context = "adhoc"

    # Frontend calls

    @app.route("/")
    def get_index():
        return send_file(os.path.join(gui_path,"index.html"))
    
    @app.errorhandler(404)
    def page_not_found(error):
        # Might be a valid angular page, serve that
        if not '.' in request.path:
            return send_file(os.path.join(gui_path,"index.html"))
        return '404 - Page was not found', 404

    @app.route("/<path:path>", methods=["GET"])
    def get_gui(path):
        return send_from_directory(gui_path, path)

    # Declare API calls

    api = Blueprint("api", __name__, url_prefix="/api")

    @api.route("/sam_reuse", methods=["GET"])
    def display_sam_reuse():
        sam_reused_return_object = []
        sam_reused = db.get_sam_reuse()
        
        an_iterator = itertools.groupby(sam_reused, lambda x : x["nthash"])
        for key, group in an_iterator: 
            sam_reused_return_object.append(list(group)) 

        return jsonify(sam_reused_return_object)
    
    @api.route("/scheduled_tasks", methods=["GET"])
    def display_scheduled_tasks():
        sam_reused = db.get_scheduled_tasks()
        return jsonify(sam_reused)
    
    @api.route("/lsa_secrets", methods=["GET"])
    def display_lsa_secrets():
        sam_reused = db.get_lsa_secrets()
        return jsonify(sam_reused)
    
    # Cookies

    cookies_api = Blueprint("cookies", __name__, url_prefix="/cookies")

    @cookies_api.route("", methods=["GET"])
    def display_cookies():
        page = request.args.get("page",default=0, type=int)
        page_size = request.args.get("page_size", default=500, type=int)
        computer_hostname_filter = request.args.get("computer_hostname", default="", type=str)
        cookie_name_filter = request.args.get("cookie_name", default="", type=str)
        cookie_value_filter = request.args.get("cookie_value", default="", type=str)
        windows_user_filter = request.args.get("windows_user", default="", type=str)
        url_filter = request.args.get("url", default="", type=str)

        cookies = db.get_cookies(
            page=page,
            page_size=page_size,
            computer_hostname=computer_hostname_filter,
            cookie_name=cookie_name_filter,
            cookie_value=cookie_value_filter,
            windows_user=windows_user_filter,
            url=url_filter,
        )
        return jsonify(cookies)
    
    @cookies_api.route("/<id>", methods=["GET"])
    def display_specific_cookie(id):
        cookie = db.get_secret(id=id)
        if cookie is None:
            return generate_error_message("No such cookie")
        return jsonify(cookie)
    
    # Secrets

    secrets_api = Blueprint("secrets", __name__, url_prefix="/secrets")

    @secrets_api.route("", methods=["GET"])
    def display_secrets():
        page = request.args.get("page",default=0, type=int)
        page_size = request.args.get("page_size", default=500, type=int)
        computer_hostname_filter = request.args.get("computer_hostname", default="", type=str)
        collector_filter = request.args.get("collector", default="", type=str)
        program_value_filter = request.args.get("program", default="", type=str)
        windows_user_filter = request.args.get("windows_user", default="", type=str)
        target_filter = request.args.get("target", default="", type=str)
        username_filter = request.args.get("username", default="", type=str)
        password_filter = request.args.get("password", default="", type=str)

        secrets = db.get_secrets(
            page=page,
            page_size=page_size,
            computer_hostname=computer_hostname_filter,
            collector=collector_filter,
            program=program_value_filter,
            windows_user=windows_user_filter,
            target=target_filter,
            username=username_filter,
            password=password_filter
            )
        
        return jsonify(secrets)
    
    @secrets_api.route("/<id>", methods=["GET"])
    def display_specific_secret(id):
        secret = db.get_secret(id=id)
        if secret is None:
            return generate_error_message("No such secret")
        return jsonify(secret)
    
    # Certificates

    certificates_api = Blueprint("certificates", __name__, url_prefix="/certificates")

    @certificates_api.route("", methods=["GET"])
    def display_certificates():
        page = request.args.get("page",default=0, type=int)
        page_size = request.args.get("page_size", default=500, type=int)

        computer_hostname_filter = request.args.get("computer_hostname", default="", type=str)
        windows_user_filter = request.args.get("windows_user", default="", type=str)
        username_filter = request.args.get("username", default="", type=str)
        client_auth_param_value = request.args.get("client_auth", default="", type=str)

        client_auth_filter = None
        if client_auth_param_value in ["True","False"]:
            client_auth_filter = client_auth_param_value == "True"


        secrets = db.get_certificates(
            page=page, 
            page_size=page_size,
            computer_hostname=computer_hostname_filter,
            windows_user=windows_user_filter,
            username=username_filter,
            client_auth=client_auth_filter,
            )
        return jsonify(secrets)
    
    @certificates_api.route("/<id>", methods=["GET"])
    def display_specific_certificate(id):
        secret = db.get_secret(id=id)
        if secret is None:
            return generate_error_message("No such certificate")
        return jsonify(secret)

    # Add API calls to the app, and run
    api.register_blueprint(cookies_api)
    api.register_blueprint(secrets_api)
    api.register_blueprint(certificates_api)

    app.register_blueprint(api)
    app.run(debug=options.v >= 2, host=options.bind, port=options.port, ssl_context=ssl_context)