from flask import request, jsonify
from functools import wraps
import jwt
from api.models import User
from api.db import app

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
            return jsonify({"error": "Invalid token"}), 403
        return f(user, *args, **kwargs)
    return decorated

def admin_only(f):
    @wraps(f)
    def decorated(user, *args, **kwargs):
        if user.role != 'admin':
            return jsonify({"error": "Admin only"}), 403
        return f(user, *args, **kwargs)
    return decorated
