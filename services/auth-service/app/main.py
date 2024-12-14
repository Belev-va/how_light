from flask import Flask, request, jsonify, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from oauthlib.oauth2 import WebApplicationClient
import os
import requests

# Flask app and database setup
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Environment variables (use dotenv in production)
GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID', 'your_google_client_id')
GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET', 'your_google_client_secret')
GOOGLE_DISCOVERY_URL = (
    "https://accounts.google.com/.well-known/openid-configuration"
)

# OAuth client setup
client = WebApplicationClient(GOOGLE_CLIENT_ID)

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # Roles: Creator, Producer, Investor
    google_id = db.Column(db.String(50), unique=True, nullable=True)

db.create_all()

# Helper function to get Google provider config
def get_google_provider_cfg():
    return requests.get(GOOGLE_DISCOVERY_URL).json()

# Routes

@app.route("/login")
def login():
    google_provider_cfg = get_google_provider_cfg()
    authorization_endpoint = google_provider_cfg["authorization_endpoint"]

    request_uri = client.prepare_request_uri(
        authorization_endpoint,
        redirect_uri=url_for("callback", _external=True),
        scope=["openid", "email", "profile"],
    )
    return redirect(request_uri)

@app.route("/callback")
def callback():
    code = request.args.get("code")

    google_provider_cfg = get_google_provider_cfg()
    token_endpoint = google_provider_cfg["token_endpoint"]

    token_url, headers, body = client.prepare_token_request(
        token_endpoint,
        authorization_response=request.url,
        redirect_url=request.base_url,
        code=code,
    )
    token_response = requests.post(
        token_url,
        headers=headers,
        data=body,
        auth=(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET),
    )

    client.parse_request_body_response(token_response.text)

    userinfo_endpoint = google_provider_cfg["userinfo_endpoint"]
    uri, headers, body = client.add_token(userinfo_endpoint)
    userinfo_response = requests.get(uri, headers=headers, data=body)

    if userinfo_response.json().get("email_verified"):
        google_id = userinfo_response.json()["sub"]
        email = userinfo_response.json()["email"]
        name = userinfo_response.json()["name"]
    else:
        return "User email not available or not verified by Google.", 400

    user = User.query.filter_by(email=email).first()
    if not user:
        user = User(
            email=email,
            name=name,
            google_id=google_id,
            role="Creator"  # Default role, can be updated later
        )
        db.session.add(user)
        db.session.commit()

    return jsonify({"message": "Login successful", "user": {
        "email": user.email,
        "name": user.name,
        "role": user.role
    }})

@app.route("/users", methods=["POST"])
def create_user():
    data = request.json
    new_user = User(
        email=data["email"],
        name=data["name"],
        role=data["role"],
    )
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": "User created successfully"}), 201

@app.route("/users/<int:user_id>", methods=["PUT"])
def update_user(user_id):
    user = User.query.get_or_404(user_id)
    data = request.json

    user.name = data.get("name", user.name)
    user.role = data.get("role", user.role)
    db.session.commit()

    return jsonify({"message": "User updated successfully"})

@app.route("/users/<int:user_id>", methods=["DELETE"])
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()

    return jsonify({"message": "User deleted successfully"})

if __name__ == "__main__":
    app.run(debug=True)
