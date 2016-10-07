from flask import Flask, jsonify, request
from flask_cors import CORS, cross_origin
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
import requests
import json
import jwt

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ECHO'] = False
app.config['TOKEN_SECRET'] = "randomString"
app.config['FACEBOOK_SECRET'] = "9ed2735184d05d91e27b0f3a9bbc0a4d"
db = SQLAlchemy(app)
CORS(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(100))
    facebook_id = db.Column(db.String(100))


    def token(self):
        payload = {
            'sub': self.id,
            'iat': datetime.utcnow(),
            'exp': datetime.utcnow() + timedelta(days=14)
        }
        token = jwt.encode(payload, app.config['TOKEN_SECRET'])
        return token.decode('unicode_escape')

@app.route('/api/auth/signup', methods=['POST'])
def signup():
    data = request.json

    email = data["email"]
    password = data["password"]

    user = User(email=email, password=password)
    db.session.add(user)
    db.session.commit()

    return jsonify(token=user.token())

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.json

    email = data.get("email")
    password = data.get("password")

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify(error="No such user"), 404

    if user.password == password:
        return jsonify(token=user.token()), 200
    else:
        return jsonify(error="Wrong email or password"), 400

@app.route('/api/user')
def user_info():
    # the token is put in the Authorization header 
    if not request.headers.get('Authorization'):
        return jsonify(error='Authorization header missing'), 401

    token = request.headers.get('Authorization').split()[1]
    try:
        payload = jwt.decode(token, app.config['TOKEN_SECRET'])
    except DecodeError:
        return jsonify(error='Invalid token'), 401
    except ExpiredSignature:
        return jsonify(error='Expired token'), 401
    else:
        user_id = payload['sub']
        user = User.query.filter_by(id=user_id).first()
        if user is None:
            return jsonify(error='Should not happen ...'), 500
        return jsonify(id=user.id, email=user.email), 200
    return jsonify(error="never reach here..."), 500

@app.route('/api/auth/facebook', methods=['POST'])
def auth_facebook():
    access_token_url = 'https://graph.facebook.com/v2.3/oauth/access_token'
    graph_api_url = 'https://graph.facebook.com/v2.5/me?fields=id,email'

    params = {
        'client_id': request.json['clientId'],
        'redirect_uri': request.json['redirectUri'],
        'client_secret': app.config['FACEBOOK_SECRET'],
        'code': request.json['code']
    }

    # Exchange authorization code for access token.
    r = requests.get(access_token_url, params=params)
    # use json.loads instead of urlparse.parse_qsl
    access_token = json.loads(r.text)

    # Step 2. Retrieve information about the current user.
    r = requests.get(graph_api_url, params=access_token)
    profile = json.loads(r.text)

    # Step 3. Create a new account or return an existing one.
    user = User.query.filter_by(facebook_id=profile['id']).first()
    if user:
        return jsonify(token=user.token())

    u = User(facebook_id=profile['id'], email=profile['email'])
    db.session.add(u)
    db.session.commit()
    return jsonify(token=u.token())

@app.route('/api/news/nyt', methods=['GET'])
def get_nyt():
    res = requests.get("https://api.nytimes.com/svc/topstories/v1/home.json?api-key=17d181ba4ac54a59bc3fde7e484cd958&offset=20")

    return res.text
if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=8000)