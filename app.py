from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token,
    get_jwt_identity
)
from flask_jwt_extended.exceptions import NoAuthorizationError, InvalidHeaderError
from backend.config import Config
import logging
from flask_cors import CORS
from datetime import datetime

# Initialize extensions
db = SQLAlchemy()
migrate = Migrate()
bcrypt = Bcrypt()
jwt = JWTManager()

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Initialize extensions
    db.init_app(app)
    migrate.init_app(app, db)
    bcrypt.init_app(app)
    jwt.init_app(app)
    
    # JWT error handler for missing token
    @jwt.unauthorized_loader
    def missing_token_callback(reason):
        return jsonify({"error": "Missing Authorization Header", "message": reason}), 401

    CORS(app, origins=["http://localhost:3000"], supports_credentials=True, allow_headers=["Content-Type", "Authorization"])

    # Configure logging
    logging.basicConfig(level=logging.DEBUG)

    # Import models
    from backend.models import User, Tenant, Payment

    # Flask error handlers for JWT exceptions
    @app.errorhandler(NoAuthorizationError)
    def handle_auth_error(e):
        return jsonify({"error": "Missing Authorization Header"}), 401

    @app.errorhandler(InvalidHeaderError)
    def handle_invalid_header_error(e):
        return jsonify({"error": "Invalid Authorization Header"}), 401

    @jwt.invalid_token_loader
    def invalid_token_callback(reason):
        return jsonify({"error": "Invalid token", "message": reason}), 401

    @app.before_request
    def log_request_info():
        app.logger.debug('Headers: %s', request.headers)
        app.logger.debug('Body: %s', request.get_data())

    @app.route('/')
    def index():
        return "Landlord Rent Tracking API"

    @app.route('/api/signup', methods=['POST'])
    def signup():
        try:
            data = request.get_json()
            if not data:
                return jsonify({"error": "No data provided"}), 400

            if not all(field in data for field in ['email', 'password']):
                return jsonify({"error": "Missing required fields: email and password"}), 400

            if User.query.filter_by(email=data['email']).first():
                return jsonify({"error": "Email already registered"}), 409

            user = User(name=data.get('name', ''), email=data['email'])
            user.set_password(data['password'])
            db.session.add(user)
            db.session.commit()

            access_token = create_access_token(identity=user.id)
            return jsonify({
                "message": "User created successfully",
                "user_id": user.id,
                "access_token": access_token
            }), 201
        except Exception as e:
            app.logger.error(f"Signup error: {str(e)}")
            return jsonify({"error": "Internal server error"}), 500

    @app.route('/api/login', methods=['POST'])
    def login():
        try:
            data = request.get_json()
            if not data:
                return jsonify({"error": "No data provided"}), 400

            if not all(field in data for field in ['email', 'password']):
                return jsonify({"error": "Missing required fields: email and password"}), 400

            user = User.query.filter_by(email=data['email']).first()
            if not user or not user.check_password(data['password']):
                return jsonify({"error": "Invalid credentials"}), 401

            access_token = create_access_token(identity=user.id)
            return jsonify({
                "message": "Login successful",
                "access_token": access_token
            }), 200
        except Exception as e:
            app.logger.error(f"Login error: {str(e)}")
            return jsonify({"error": "Internal server error"}), 500

    @app.route('/api/tenants', methods=['POST'])
    @jwt_required()
    def create_tenant():
        try:
            current_user_id = get_jwt_identity()
            data = request.get_json()
            if not data:
                return jsonify({"error": "No data provided"}), 400

            required_fields = ['name', 'phone', 'house_number', 'rent_amount']
            missing = [f for f in required_fields if f not in data]
            if missing:
                return jsonify({"error": f"Missing fields: {', '.join(missing)}"}), 400

            if not data['phone'].isdigit() or len(data['phone']) < 10:
                return jsonify({"error": "Invalid phone number"}), 400

            try:
                rent_amount = float(data['rent_amount'])
                if rent_amount <= 0:
                    return jsonify({"error": "Rent must be positive"}), 400
            except (TypeError, ValueError):
                return jsonify({"error": "Invalid rent amount"}), 400

            tenant = Tenant(
                name=data['name'],
                phone=data['phone'],
                house_number=data['house_number'],
                rent_amount=rent_amount,
                balance=rent_amount,
                user_id=current_user_id
            )
            db.session.add(tenant)
            db.session.commit()
            return jsonify(tenant.serialize()), 201
        except Exception as e:
            app.logger.error(f"Create tenant error: {str(e)}")
            return jsonify({"error": "Internal server error"}), 500

    @app.route('/api/tenants', methods=['GET'])
    @jwt_required()
    def get_tenants():
        try:
            current_user_id = get_jwt_identity()
            tenants = Tenant.query.filter_by(user_id=current_user_id).all()
            return jsonify([t.serialize() for t in tenants]), 200
        except Exception as e:
            app.logger.error(f"Get tenants error: {str(e)}")
            return jsonify({"error": "Internal server error"}), 500

    @app.route('/api/payments', methods=['POST'])
    @jwt_required()
    def record_payment():
        try:
            current_user_id = get_jwt_identity()
            data = request.get_json()
            if not data:
                return jsonify({"error": "No data provided"}), 400

            required_fields = ['tenant_id', 'amount', 'mpesa_code']
            missing = [f for f in required_fields if f not in data]
            if missing:
                return jsonify({"error": f"Missing fields: {', '.join(missing)}"}), 400

            tenant = Tenant.query.filter_by(id=data['tenant_id'], user_id=current_user_id).first()
            if not tenant:
                return jsonify({"error": "Tenant not found"}), 404

            mpesa_code = data['mpesa_code'].strip().upper()
            if not mpesa_code or len(mpesa_code) < 5:
                return jsonify({"error": "Invalid MPesa code"}), 400

            if Payment.query.filter_by(mpesa_code=mpesa_code).first():
                return jsonify({"error": "MPesa code already used"}), 409

            try:
                amount = float(data['amount'])
                if amount <= 0 or amount > tenant.balance:
                    return jsonify({"error": "Invalid payment amount"}), 400
            except (TypeError, ValueError):
                return jsonify({"error": "Invalid amount"}), 400

            payment = Payment(amount=amount, mpesa_code=mpesa_code, tenant_id=tenant.id)
            tenant.balance -= amount
            db.session.add(payment)
            db.session.commit()
            return jsonify({"message": "Payment recorded", "tenant": tenant.serialize()}), 201
        except Exception as e:
            app.logger.error(f"Record payment error: {str(e)}")
            return jsonify({"error": "Internal server error"}), 500

    @app.route('/api/payments/<int:tenant_id>', methods=['GET'])
    @jwt_required()
    def get_payments(tenant_id):
        try:
            current_user_id = get_jwt_identity()
            tenant = Tenant.query.filter_by(id=tenant_id, user_id=current_user_id).first()
            if not tenant:
                return jsonify({"error": "Tenant not found"}), 404

            payments = Payment.query.filter_by(tenant_id=tenant.id).all()
            return jsonify([{
                "id": p.id,
                "amount": p.amount,
                "mpesa_code": p.mpesa_code,
                "timestamp": p.timestamp.isoformat()
            } for p in payments]), 200
        except Exception as e:
            app.logger.error(f"Get payments error: {str(e)}")
            return jsonify({"error": "Internal server error"}), 500

    # General error handlers
    @app.errorhandler(400)
    def bad_request(error): return jsonify({"error": "Bad request"}), 400

    @app.errorhandler(401)
    def unauthorized(error): return jsonify({"error": "Unauthorized"}), 401

    @app.errorhandler(404)
    def not_found(error): return jsonify({"error": "Not found"}), 404

    @app.errorhandler(500)
    def internal_error(error): return jsonify({"error": "Server error"}), 500

    return app

# Create app instance
app = create_app()

if __name__ == '__main__':
    app.run(debug=True)
