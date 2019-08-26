import logging
from flask import Flask, json, request, redirect, render_template, make_response, url_for
import flask_login
from .shorten import UrlShortener
from functools import wraps
from bernhard import Client
from riemann_wrapper import riemann_wrapper
from urllib.parse import urlparse
from . import config

app = Flask(__name__)
shrt = UrlShortener()
logger = logging.getLogger()

logger.info("starting up")
try:
    riemann_client = Client(host=config.RIEMANN_HOST,
                            port=config.RIEMANN_PORT)
    riemann_client.send({'metric': 1, 
                         'service': 
                         'url-shortener.startup', 
                         'ttl': 3600})
except:
    riemann_client=None

wrap_riemann = riemann_wrapper(client=riemann_client, prefix='url-shortener.')

app.secret_key = config.SECRET_KEY
login_manager = flask_login.LoginManager()
login_manager.init_app(app)

# Our mock database.
users = {'test': {'password': 'test'}}

class User(flask_login.UserMixin):
    pass

@login_manager.user_loader
def user_loader(email):
    if email not in users:
        return

    user = User()
    user.id = email
    return user

@login_manager.request_loader
def request_loader(request):
    email = request.form.get('email')
    if email not in users:
        return

    user = User()
    user.id = email

    # DO NOT ever store passwords in plaintext and always compare password
    # hashes using constant-time comparison!
    user.is_authenticated = request.form['password'] == users[email]['password']

    return user

@login_manager.unauthorized_handler
def unauthorized_callback():
    return redirect('/login?next=' + request.path)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return '''
               <form action='login' method='POST'>
                <input type='text' name='email' id='email' placeholder='email'/>
                <input type='password' name='password' id='password' placeholder='password'/>
                <input type='submit' name='submit'/>
               </form>
               '''

    email = request.form['email']
    if request.form['password'] == users[email]['password']:
        user = User()
        user.id = email
        flask_login.login_user(user)
        return redirect(url_for('index'))

    return 'Bad login'

@app.route('/logout')
def logout():
    flask_login.logout_user()
    return 'Logged out'

## template pushing routes
@app.route('/')
@flask_login.login_required
@wrap_riemann('home')
def index():
    return render_template('index.html')

@app.route('/404')
@wrap_riemann('missing', tags=['http_404'])
def missing():
    return render_template('missing.html')

@app.route('/400')
@wrap_riemann('invalid', tags=['http_400'])
def invalid():
    return render_template('invalid')

## short url lookup
@app.route('/<code>')
@wrap_riemann('lookup')
def lookup(code):
    url = shrt.lookup(code)
    if not url:
        return redirect('/404')
    else:
        return redirect(url)
    
## short url generation
##
## If JSON is fed, we shorten and reply in JSON as well
## If a Form is posted we reply in HTML
## Otherwise we redirect to a failure page
@app.route('/', methods=['POST'])
@flask_login.login_required
@wrap_riemann('creation')
def shorten_url():
    if request.json and 'url' in request.json:
        u = urlparse(request.json['url'])
        if u.netloc == '':
            url = 'http://' + request.json['url']
        else:
            url = request.json['url']
        res = shrt.shorten(url)
        logger.debug("shortened %s to %s" % (url, res))
        response = make_response(json.dumps(res))
        response.headers['Content-Type'] = 'application/json'
        return response

    elif request.form and 'url' in request.form:
        u = urlparse(request.form['url'])
        if u.netloc == '':
            url = 'http://' + request.form['url']
        else:
            url = request.form['url']
        if request.form.get('label', None): 
            label = request.form['label']
            res = shrt.shorten(url, label=label)
        else:
            res = shrt.shorten(url)
        logger.debug("shortened %s to %s" % (url, res))
        return render_template('result.html', result=res)

    else:
        logger.info("invalid shorten request")
        return redirect('/400')
