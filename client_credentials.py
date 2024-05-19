from flask import Flask
from authlib.integrations.flask_client import OAuth

app = Flask(__name__)
oauth = OAuth(app)

google = oauth.register(
    name = 'google',
    client_id = '165893851990-nk98m19q3ks3p4eq4e7tsuc66f64eivk.apps.googleusercontent.com',
    client_secret = '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',
    authorize_url= 'http://127.0.0.1:5000/google_auth',
    access_token_url = 'https://accounts.google.com/o/oauth2/token',
    access_token_params = None,
    api_base_url = 'https://www.googleapis.com/oauth2/v1/',
    client_kwargs={'scope': 'openid profile email'},
)
