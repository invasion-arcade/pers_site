from flask import Flask
from flask import render_template, redirect, request, url_for
from flask_login import (
    LoginManager,
    current_user,
    login_required,
    login_user,
    logout_user
)
from authlib.integrations.flask_client import OAuth

import json
import sqlite3
from oauthlib.oauth2 import WebApplicationClient
import requests
from db import init_db_command
from user import User

app = Flask(__name__, static_folder="assets")
app.secret_key = ''
GOOGLE_CLIENT_ID = ''
GITHUB_CLIENT_ID = ''
GITHUB_CLIENT_SECRET = ''
GOOGLE_CLIENT_SECRET = ''
GOOGLE_DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration"
login_manager = LoginManager()
oauth = OAuth(app)
github = oauth.register(

    name='github',

    client_id=GITHUB_CLIENT_ID,

    client_secret=GITHUB_CLIENT_SECRET,

    access_token_url='https://github.com/login/oauth/access_token',

    access_token_params=None,

    authorize_url='https://github.com/login/oauth/authorize',

    authorize_params=None,

    api_base_url='https://api.github.com/'
)

try:
    init_db_command()
except sqlite3.OperationalError:
    pass

gclient = WebApplicationClient(GOOGLE_CLIENT_ID)
ghclient = WebApplicationClient(GITHUB_CLIENT_ID)

@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)

@app.route('/')
def home():
    if current_user.is_authenticated:
        return render_template('auth.html', name=current_user.name)
    else:
        return render_template('not_auth.html')

def get_google_provider_cfg():
    return requests.get(GOOGLE_DISCOVERY_URL).json()

@app.route("/glogin")
def glogin():
    google_provider_cfg = get_google_provider_cfg()
    authorization_endpoint = google_provider_cfg["authorization_endpoint"]
    request_uri = gclient.prepare_request_uri(
        authorization_endpoint,
        redirect_uri=request.base_url + "/callback",
        scope=["openid", "email", "profile"],
    )
    return redirect(request_uri)


@app.route("/glogin/callback")
def gcallback():
    code = request.args.get("code")
    google_provider_cfg = get_google_provider_cfg()
    token_endpoint = google_provider_cfg["token_endpoint"]
    token_url, headers, body = gclient.prepare_token_request(
        token_endpoint,
        authorization_response=request.url,
        redirect_url=request.base_url,
        code=code
    )
    token_response = requests.post(
        token_url,
        headers=headers,
        data=body,
        auth=(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET),
    )
    gclient.parse_request_body_response(json.dumps(token_response.json()))
    userinfo_endpoint = google_provider_cfg["userinfo_endpoint"]
    uri, headers, body = gclient.add_token(userinfo_endpoint)
    userinfo_response = requests.get(uri, headers=headers, data=body)
    if userinfo_response.json().get("email_verified"):
        unique_id = (userinfo_response.json()["sub"]) * 2
        users_name = userinfo_response.json()["given_name"]
    else:
        return "User email not available or not verified by Google.", 400
    user = User(
        id_=unique_id, name=users_name
    )
    if not User.get(unique_id):
        User.create(unique_id, users_name)
    login_user(user)
    return redirect(url_for("home"))


@app.route("/ghlogin")
def ghlogin():
    redirect_url = url_for("ghcallback", _external=True)
    return github.authorize_redirect(redirect_url)


@app.route("/ghlogin/callback")
def ghcallback():
    token = github.authorize_access_token()
    resp = github.get('user', token=token)
    profile = resp.json()
    unique_id = profile["id"] * 2 + 1
    user = User(
        id_=unique_id, name=profile["login"]
    )
    if not User.get(unique_id):
        User.create(unique_id, profile["login"])
    login_user(user)
    return redirect(url_for("home"))


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("home"))


if __name__ == "__main__":
    login_manager.init_app(app)
    app.run(host='0.0.0.0', port=443, ssl_context="adhoc")