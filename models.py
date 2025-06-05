from datetime import datetime
from backend.app import db, bcrypt
from flask_jwt_extended import create_access_token

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    tenants = db.relationship('Tenant', backref='landlord', lazy=True)

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

    def get_jwt(self):
        return create_access_token(identity=self.id)

class Tenant(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    house_number = db.Column(db.String(10), nullable=False)
    rent_amount = db.Column(db.Float, nullable=False)  # Monthly rent
    balance = db.Column(db.Float, default=0)  # Negative balance means overdue
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    payments = db.relationship('Payment', backref='tenant', lazy=True)

    def serialize(self):
        return {
            "id": self.id,
            "name": self.name,
            "phone": self.phone,
            "house_number": self.house_number,
            "rent_amount": self.rent_amount,
            "balance": self.balance,
            "paid": abs(min(0, self.balance)),  # Amount paid this period
            "due": max(0, self.balance)  # Positive balance means overdue
        }

class Payment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    amount = db.Column(db.Float, nullable=False)
    mpesa_code = db.Column(db.String(20), unique=True, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenant.id'), nullable=False)