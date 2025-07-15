# app.py

from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import qrcode, io
from datetime import datetime, timedelta
import jwt
from functools import wraps
import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///warehouse.db'
app.config['SECRET_KEY'] = 'supersecretkey'
db = SQLAlchemy(app)

### MODELS ###
class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(64), unique=True, nullable=False)
    name = db.Column(db.String(120), nullable=False)
    quantity = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), default="staff")

@app.before_first_request
def create_tables():
    db.create_all()
    if not User.query.filter_by(username="admin").first():
        hashed_pw = generate_password_hash("admin123", method="sha256")
        db.session.add(User(username="admin", password=hashed_pw, role="admin"))
        db.session.commit()

### AUTH ###
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("Authorization")
        if not token:
            return jsonify({"error": "Token missing"}), 403
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            user = User.query.get(data['user_id'])
        except:
            return jsonify({"error": "Token invalid"}), 403
        return f(user, *args, **kwargs)
    return decorated

def admin_only(f):
    @wraps(f)
    def decorated(user, *args, **kwargs):
        if user.role != 'admin':
            return jsonify({"error": "Admin only"}), 403
        return f(user, *args, **kwargs)
    return decorated

### ROUTES ###
@app.route("/login", methods=["POST"])
def login():
    data = request.json
    user = User.query.filter_by(username=data["username"]).first()
    if not user or not check_password_hash(user.password, data["password"]):
        return jsonify({"error": "Invalid credentials"}), 401
    token = jwt.encode({
        "user_id": user.id,
        "exp": datetime.utcnow() + timedelta(hours=2)
    }, app.config['SECRET_KEY'])
    return jsonify({"token": token, "role": user.role})

@app.route("/add_product", methods=["POST"])
@token_required
@admin_only
def add_product(user):
    data = request.json
    product = Product.query.filter_by(code=data["code"]).first()
    if product:
        product.quantity += data["quantity"]
    else:
        product = Product(name=data["name"], code=data["code"], quantity=data["quantity"])
        db.session.add(product)
    db.session.commit()
    return jsonify({"message": "Product added/updated"})

@app.route("/export_product", methods=["POST"])
@token_required
@admin_only
def export_product(user):
    data = request.json
    product = Product.query.filter_by(code=data["code"]).first()
    if not product or product.quantity < data["quantity"]:
        return jsonify({"error": "Not enough stock"}), 400
    product.quantity -= data["quantity"]
    db.session.commit()
    return jsonify({"message": "Product exported"})

@app.route("/inventory", methods=["GET"])
@token_required
def inventory(user):
    products = Product.query.all()
    return jsonify([
        {"code": p.code, "name": p.name, "quantity": p.quantity}
        for p in products
    ])

@app.route("/generate_qr", methods=["POST"])
@token_required
def generate_qr(user):
    data = request.json
    qr = qrcode.make(data["code"])
    buf = io.BytesIO()
    qr.save(buf, format="PNG")
    buf.seek(0)
    return buf.read(), 200, {'Content-Type': 'image/png'}

if __name__ == "__main__":
    app.run()
