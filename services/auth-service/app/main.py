from flask import Flask, request, jsonify, redirect, url_for
from authlib.integrations.flask_client import OAuth
import os

app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['GOOGLE_CLIENT_ID'] = 'your-google-client-id'
app.config['GOOGLE_CLIENT_SECRET'] = 'your-google-client-secret'
app.config['GOOGLE_DISCOVERY_URL'] = "https://accounts.google.com/.well-known/openid-configuration"

oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=app.config['GOOGLE_CLIENT_ID'],
    client_secret=app.config['GOOGLE_CLIENT_SECRET'],
    access_token_url='https://accounts.google.com/o/oauth2/token',
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    client_kwargs={'scope': 'openid email profile'},
)


@app.route('/login')
def login():
    return google.authorize_redirect(url_for('authorize', _external=True))


@app.route('/authorize')
def authorize():
    token = google.authorize_access_token()
    user_info = google.get('userinfo').json()
    # Process user info (e.g., store in DB)
    return jsonify(user_info)


@app.route('/register', methods=['POST'])
def register():
    data = request.json
    # Add user registration logic
    return jsonify({"message": "User registered successfully"}), 201


@app.route('/roles', methods=['GET'])
def get_roles():
    roles = ["creator", "producer", "investor"]
    return jsonify(roles)


if __name__ == '__main__':
    app.run(debug=True)
