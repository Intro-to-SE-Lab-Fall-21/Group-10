from flask import Flask, request, render_template, redirect, session, jsonify, json, send_from_directory, url_for
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from flask_bootstrap import Bootstrap
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
import atexit
import datetime
import email
import imaplib
import mailbox
import json
import os
import base64
import html2text
import hashlib

app = Flask(__name__,static_url_path='/static')
app.config['SECRET_KEY'] = 'NOBODY-CAN-GUESS-THIS'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///dogpile_db.db'
Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class UserConfig(UserMixin, db.Model):
    __tablename__ = 'userConfig'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20))
    password = db.Column(db.String(80))
    email = db.Column(db.String(30),unique=True)
    role = db.relationship("Role",secondary="userRoles")

# Define the Role data-model
class Role(db.Model):
    __tablename__ = 'role'
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(50), unique=True)

# Define the UserRoles association table
class UserRoles(db.Model):
    __tablename__ = 'userRoles'
    urid = db.Column(db.Integer(), primary_key=True)
    uid = db.Column(db.Integer(), db.ForeignKey('userConfig.id', ondelete='CASCADE'))
    rid = db.Column(db.Integer(), db.ForeignKey('role.id', ondelete='CASCADE'))

imap_host = 'imap.gmail.com'
imap_user = 'group10.dogpile.client@gmail.com'
imap_pass = 'qXD?k*g3+b2P'
global_mail_list = []

@app.template_filter()
def datetimefilter(value, format='%Y/%m/%d %H:%M'):
    return value.strftime(format)
app.jinja_env.filters['datetimefilter'] = datetimefilter

def getemaillist():
    global global_mail_list
    mail_list = [] 
    mail = imaplib.IMAP4_SSL(imap_host)
    mail.login(imap_user, imap_pass)
    mail.list()
    mail.select('inbox')
    result, data = mail.uid('search', None, "ALL") # (ALL/UNSEEN)
    i = len(data[0].split())

    for x in range(i):
        latest_email_uid = data[0].split()[x]
        result, email_data = mail.uid('fetch', latest_email_uid, '(RFC822)')
        # result, email_data = conn.store(num,'-FLAGS','\\Seen') 
        # this might work to set flag to seen, if it doesn't already
        raw_email = email_data[0][1]
        raw_email_string = raw_email.decode('utf-8')
        email_message = email.message_from_string(raw_email_string)
        #print (email_message)
        # Header Details
        date_tuple = email.utils.parsedate_tz(email_message['Date'])
        if date_tuple:
            local_date = datetime.datetime.fromtimestamp(email.utils.mktime_tz(date_tuple))
            local_message_date = "%s" %(str(local_date.strftime("%a, %m/%d/%Y, %H:%M %p")))
        realname, addr = email.utils.parseaddr(email_message['from'])
        email_to = str(email.header.make_header(email.header.decode_header(email_message['To'])))
        subject = str(email.header.make_header(email.header.decode_header(email_message['Subject'])))
        mail_item = {"uid": (latest_email_uid).decode("ascii"), "email_from_name":realname,"email_from_addr":addr, "email_to": email_to, "subject": subject, "date":local_message_date}
        mail_list.append(mail_item)
    else:
        global_mail_list = mail_list
def getMessage(m = None):
    if m is not None:
        mail_list = []
        filename = None
        mail = imaplib.IMAP4_SSL(imap_host)
        mail.login(imap_user, imap_pass)
        mail.list()
        mail.select('inbox')
        result, data = mail.uid('search', None, "ALL") # (ALL/UNSEEN)
        mID = int(m)
        latest_email_uid = data[0].split()[mID-1]
        result, email_data = mail.uid('fetch', latest_email_uid, '(RFC822)')
        # result, email_data = conn.store(num,'-FLAGS','\\Seen') 
        # this might work to set flag to seen, if it doesn't already
        raw_email = email_data[0][1]
        raw_email_string = raw_email.decode('utf-8')
        email_message = email.message_from_string(raw_email_string)
        #print (email_message)
        # Header Details
        for part in email_message.walk():
            if part.get_content_maintype() == 'multipart':
                continue
            if part.get('Content-Disposition') is None:
                continue
            filename = part.get_filename()
            att_path = os.path.join('attachments', filename)

            if not os.path.isfile(att_path):
                fp = open(att_path, 'wb')
                fp.write(part.get_payload(decode=True))
                fp.close()
        if email_message.is_multipart():
            charset = part.get_content_charset()
            if charset is None:
                charset = 'utf-8'
            for payload in email_message.get_payload():
                for part in email_message.walk():
                    if part.get_content_type() == 'text/plain':
                        body = str(part.get_payload(decode=True), str(charset), "ignore").encode('utf8', 'replace')
                    if part.get_content_type() == 'text/html':
                        body = str(part.get_payload(decode=True), str(charset), "ignore").encode('utf8', 'replace')
                break
        else:
            text = f"{email_message.get_payload(decode=True)}"
            html = text.replace("b'", "")
            h = html2text.HTML2Text()
            h.ignore_links = false
            output = (h.handle(f'''{html}''').replace("\\r\\n", ""))
            output = output.replace("'", "")
            body = output
        realname, addr = email.utils.parseaddr(email_message['from'])
        email_to = str(email.header.make_header(email.header.decode_header(email_message['To'])))
        subject = str(email.header.make_header(email.header.decode_header(email_message['Subject'])))
        date_tuple = email.utils.parsedate_tz(email_message['Date'])
        if date_tuple:
            local_date = datetime.datetime.fromtimestamp(email.utils.mktime_tz(date_tuple))
            local_message_date = "%s" %(str(local_date.strftime("%a, %m/%d/%Y, %H:%M %p")))
        mail_message = {"uid": (latest_email_uid).decode("ascii"), "email_from_name":realname,"email_from_addr":addr, "email_to": email_to, "subject": subject,
         "date":local_message_date,"body":body.decode(), "attachments":filename}
        mail_list.append(mail_message)
        return (mail_list)
    else:
        return ("")
def getConfig():
    configInfo = open("emailConfig.txt", 'r')
    data = {"host":configInfo.readline(),"port": configInfo.readline(), "protocol": configInfo.readline()}
    configInfo.close();
    return (data)

def userAuth():
    userInfoFile = open("userConfig.txt", 'r')
    userEmail = userInfoFile.readline()
    userPassword = userInfoFile.readline()
    userInfoFile.close()
    userLen = len(userEmail) - userEmail.count('\n')
    passLen = len(userPassword) - userPassword.count('\n')
    if userLen >0 and passLen >0:
        return True
    else:
      return False


@login_manager.user_loader
def load_user(user_id):
    return UserConfig.query.get(int(user_id))

class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=20)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=5, max=80)])
    remember = BooleanField('remember me')


class RegisterForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=20)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=5, max=80)])
    email = StringField('email', validators=[InputRequired(), Email(message="Invalid Email"), Length(min=6, max=30)])


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = UserConfig.query.filter_by(username=form.username.data).first()
        if user:
            # compares the password hash in the db and the hash of the password typed in the form
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                return redirect(url_for('inbox'))
        return 'invalid username or password'

    return render_template('login.html', form=form)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        # add the user form input which is form.'field'.data into the column which is 'field'
        user_role = UserRoles(rid='2')
        
        new_user = UserConfig(username=form.username.data, password=hashed_password, email=form.email.data,role=[user_role])
        db.session.add(new_user)
        db.session.commit()
        return 'new user has been created bro!'

    return render_template('signup.html', form=form)



@app.route('/dashboard')
@login_required
def dashboard():
    role_names = (role.name for role in current_user.role)
    return render_template('dashboard.html', name=current_user.username,role=role_names)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/attachments/<path:filename>')
def getFile(filename):
    try:
        return send_from_directory('attachments', filename, as_attachment=True)
    except FileNotFoundError:
        abort(404)

@app.route("/inbox")
@app.route("/inbox/<idname>")
@login_required
def inbox(idname = None):
    return render_template('_inbox.html', reply = None, activemessage = idname, data=global_mail_list, email_body = getMessage(idname), config = getConfig())

@app.route("/inbox/<idname>/reply")
@app.route("/inbox/<idname>/forward")

def homereply(idname = None):
    if userAuth() == False:
        return redirect("/")
    return render_template('_inbox.html', reply = idname, activemessage = None, data=global_mail_list, email_body = getMessage(idname), config = getConfig())

@app.route("/send", methods=['POST'])
def send():
    formTo = request.form['To']
    formFrom = request.form['CC']
    formBody = request.form['emailArea']

    message = formTo + "<br>"
    message += formFrom + "<br>"
    message += formBody
    return (message)

# scheduler = BackgroundScheduler()
# scheduler.start()
# scheduler.add_job(
#     func=getemaillist,
#     trigger=IntervalTrigger(seconds=30),
#     id='get mail every 30 seconds',
#     name='get mail every 30 seconds',
#     replace_existing=True)
# # Shut down the scheduler when exiting the app
# atexit.register(lambda: scheduler.shutdown())

getemaillist()

