from flask import Flask, jsonify, url_for, request, redirect, session
from werkzeug.urls import url_parse
from datetime import datetime
from authlib.integrations.flask_client import OAuth
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from functools import wraps
import os
import dotenv
import base64
import openai

dotenv.load_dotenv()

def custom_login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.is_anonymous:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL")

api_key = os.getenv("OPEN_API_KEY")
openai.api_key = api_key

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

oauth = OAuth(app)
github = oauth.register(
    name='github',
    client_id=os.getenv("GITHUB_CLIENT_ID"),
    client_secret=os.getenv("GITHUB_CLIENT_SECRET"),
    access_token_url='https://github.com/login/oauth/access_token',
    authorize_url='https://github.com/login/oauth/authorize',
    api_base_url='https://api.github.com/',
    client_kwargs={'scope': 'user:email repo' },
)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    github_token = db.Column(db.JSON, nullable=False)


with app.app_context():
    db.create_all()

def refresh_github_token():
    if current_user.is_authenticated:
        github.token = current_user.github_token
        print("Token:", github.token)
    else:
        github.token = None

@login_manager.user_loader
def load_user(user_id):
    if user_id is not None and user_id != 'None':
        return User.query.get(int(user_id))
    return None

@app.route("/")
def home():
    return "Welcome to the security smart contract audit API!"

@app.route('/login')
def login():
    session['next_url'] = request.args.get('next') or request.referrer or None
    redirect_uri = url_for('callback', _external=True, _scheme='https')
    return github.authorize_redirect(redirect_uri)

@app.route('/callback')
def callback():
    token = github.authorize_access_token()
    resp = github.get('user')
    user_info = resp.json()
    user = User.query.filter_by(username=user_info['login']).first()

    if user is None:
        user = User(username=user_info['login'], github_token=token)
        db.session.add(user)
        db.session.commit()
    else:
        user.github_token = token
        db.session.commit()

    login_user(user)
    
    next_url = session.pop('next_url', None)
    
    if not next_url or url_parse(next_url).netloc != '':
        next_url = url_for('home')
    
    return redirect(next_url)

@app.route('/protected')
@custom_login_required
def protected():
    return f'Hello, {current_user.username}!'

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return 'Logged out!'

@app.route('/repos')
@custom_login_required
def repos():
    refresh_github_token()
    resp = github.get('user/repos')
    repos = resp.json()
    shown_repos = [repo['name'] for repo in repos]
    return jsonify(repos)

@app.route('/repo_contents/<user>/<repo>')
@login_required
def repo_contents(user, repo):
    refresh_github_token()
    resp = github.get(f'repos/{user}/{repo}')
    contents = resp.json()
    
    file_names = []
    for item in contents:
        if item['type'] == 'file':
            file_names.append(item['name'])

    return jsonify(file_names)

@app.route('/read_file/<user>/<repo>/<path:folder>/<file_name>')
@login_required
def read_file(user, repo, folder, file_name):
    refresh_github_token()
    file_path = f'{folder}/{file_name}'
    resp = github.get(f'repos/{user}/{repo}/contents/{file_path}')
    content = resp.json()
    

    decoded_content = base64.b64decode(content['content']).decode('utf-8')
    completion = openai.ChatCompletion.create(
        model="gpt-3.5-turbo", 
        messages=[{"role": "user", "content": f'A bit of context, this is a smart contract within the Near Protocol. Tell me everything that is wrong with the below code from a security perspective and how somebody can exploit each issue.  \n\n{decoded_content}'}]
        )
    return completion

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=os.getenv("PORT", default=5000))
