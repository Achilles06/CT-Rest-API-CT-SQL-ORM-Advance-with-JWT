from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from models import db
from blueprints.employee import employee_bp
from blueprints.products import product_bp
from blueprints.order import order_bp
from blueprints.customer import customer_bp
from blueprints.production import production_bp

# Initialize Limiter
limiter = Limiter(key_func=get_remote_address)

def create_app():
    app = Flask(__name__)
    
    # Configuration settings
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///instance/factory.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # Initialize extensions
    db.init_app(app)
    limiter.init_app(app)

    # Register Blueprints
    app.register_blueprint(employee_bp, url_prefix='/employees')
    app.register_blueprint(product_bp, url_prefix='/products')
    app.register_blueprint(order_bp, url_prefix='/orders')
    app.register_blueprint(customer_bp, url_prefix='/customers')
    app.register_blueprint(production_bp, url_prefix='/production')

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True)


from flask import request, jsonify
from models import User
from utils.util import encode_token, decode_token
from functools import wraps

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    user = session.query(User).filter_by(username=username).first()
    if user and user.check_password(password):
        token = encode_token(user.id)
        return jsonify({"message": "Login successful", "token": token})
    return jsonify({"message": "Invalid credentials"}), 401

def role_required(required_role):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            token = request.headers.get('Authorization')
            if not token:
                return jsonify({"message": "Missing token"}), 403
            user_id = decode_token(token.split(" ")[1])
            if isinstance(user_id, str):
                return jsonify({"message": user_id}), 403
            user = session.query(User).get(user_id)
            if user and user.role == required_role:
                return func(*args, **kwargs)
            return jsonify({"message": "Unauthorized access"}), 403
        return wrapper
    return decorator

@app.route('/create-product', methods=['POST'])
@role_required('admin')
def create_product():
    data = request.get_json()
    return jsonify({"message": "Product created successfully"})
