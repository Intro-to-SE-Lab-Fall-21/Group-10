from flask import Flask, render_template, flash, redirect, url_for, request,send_from_directory
from flask_wtf import FlaskForm
from wtforms import StringField, IntegerField, PasswordField, BooleanField, SubmitField
from wtforms.validators import ValidationError, DataRequired, Email, EqualTo
from flask_sqlalchemy import SQLAlchemy # as _BaseSQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.urls import url_parse
from flask_login import LoginManager, UserMixin, current_user, login_user, logout_user, login_required
from functools import wraps
import datetime
import email
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from email.header import Header
from email.header import decode_header
from email.utils import formataddr
#import secrets
import keyring
import email
import imaplib
import smtplib
import ssl
import mailbox
import html2text
import json
import os

app = Flask(__name__)

login = LoginManager(app)
login.login_view = 'login'
login.login_message_category = 'danger'
global_mail_list = []
global_search_list = []

app.config['SECRET_KEY']='d0gp1l3k3y-not-secret-really'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///dogpile_db.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


#class SQLAlchemy(_BaseSQLAlchemy):
#     def apply_pool_defaults(self, app, options):
#        super(SQLAlchemy, self).apply_pool_defaults(app, options)
#        options["pool_pre_ping"] = True

db = SQLAlchemy(app)

#Form Classes

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Sign In')

class RegistrationForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm = PasswordField('Repeat Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user is not None:
            raise ValidationError('Please use a different username.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is not None:
            raise ValidationError('Please use a different email address.')

class NewUserForm(FlaskForm):
    name = StringField('Name: ', validators=[DataRequired()])
    username = StringField('Username: ', validators=[DataRequired()])
    email = StringField('Email: ', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm = PasswordField('Repeat Password', validators=[DataRequired(), EqualTo('password')])
    access = IntegerField('Access: ')
    submit = SubmitField('Create User')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user is not None:
            raise ValidationError('Please use a different username.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is not None:
            raise ValidationError('Please use a different email address.')

class UserDetailForm(FlaskForm):
    id = IntegerField('Id: ')
    name = StringField('Name: ', validators=[DataRequired()])
    username = StringField('Username: ', validators=[DataRequired()])
    email = StringField('Email: ', validators=[DataRequired(), Email()])
    access = IntegerField('Access: ')

class UserPasswordForm(FlaskForm):
    id = IntegerField('Id: ')
    password = PasswordField('Password', validators=[DataRequired()])
    confirm = PasswordField('Confirm', validators=[DataRequired(), EqualTo('password')])

class EmailConfigForm(FlaskForm):
    id = IntegerField('Id: ')
    incoming_host = StringField('Incoming Host: ', validators=[DataRequired()])
    outgoing_host = StringField('Outcoming Host: ', validators=[DataRequired()])
    incoming_port = IntegerField('Incoming Port: ')
    outgoing_port = IntegerField('Outgoing Port: ')
    emailaccount = StringField('Email/Server Account: ', validators=[DataRequired()])
    emailpassword = PasswordField('Password: ', validators=[DataRequired()])
    emailconfirm = PasswordField('Confirm', validators=[DataRequired(), EqualTo('emailpassword')])

#change to db based in next version
ACCESS = {
    'guest': 0,
    'user': 1,
    'admin': 2
}

## db table classes
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(100))
    username = db.Column(db.String(30))
    password_hash = db.Column(db.String(128))
    access = db.Column(db.Integer)

    def is_admin(self):
        return self.access == ACCESS['admin']

    def is_user(self):
        return self.access == ACCESS['user']

    def allowed(self, access_level):
        return self.access >= access_level

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return '<User {0}>'.format(self.username)

class MailConfig(UserMixin, db.Model):
    __tablename__ = 'mailConfig'
    uid = db.Column(db.Integer, primary_key=True)
    incomingHost = db.Column(db.String(30))
    incomingPort = db.Column(db.Integer)
    outgoingHost = db.Column(db.String(30))
    outgoingPort = db.Column(db.Integer)
    account = db.Column(db.String(30))

    def set_password(self, account ,password):
        keyring.set_password("dogpile_mail_"+str(self.uid),account,password)

    def get_password(self, account):
        return keyring.get_password("dogpile_mail_"+str(self.uid),account)


@login.user_loader
def load_user(id):
    return User.query.get(int(id))

def requires_access_level(access_level):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated: #the user is not logged in
                return redirect(url_for('login'))
            if not current_user.allowed(access_level):
                flash("Access Denied, my friend!", 'danger')
                return redirect(url_for('index'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

### Routes

# index
@app.route('/')
@app.route('/index')
def index():
    return render_template('index.html')

# register
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        name = form.name.data
        username = form.username.data
        user = User(id = None, name=name, username=username, email=form.email.data,access=ACCESS['user'])
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Congratulations, you are now a registered user!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html',  pageTitle='Register | dogPile Email Client', form=form)

# login
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Invalid username or password', 'danger')
            return redirect(url_for('login'))
        login_user(user, remember=form.remember_me.data)
        next_page = request.args.get('next')
        if not next_page or url_parse(next_page).netloc != '':
            next_page = url_for('index')
        return redirect(next_page)
    return render_template('login.html',  pageTitle='Login | dogPile Email Client', form=form)

#logout
@app.route('/logout')
def logout():
    logout_user()
    flash('You have successfully logged out.', 'success')
    return redirect(url_for('index'))

#settings
@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    user = User.query.get_or_404(current_user.id)
    exist_mail = MailConfig.query.filter_by(uid=current_user.id).first()
    userForm = UserPasswordForm()
    if(exist_mail):
        configForm = EmailConfigForm(incoming_host=exist_mail.incomingHost,outgoing_host=exist_mail.outgoingHost,incoming_port=exist_mail.incomingPort,
            outgoing_port=exist_mail.outgoingPort,emailaccount=exist_mail.account)
    else:
        configForm = EmailConfigForm()

    if userForm.validate_on_submit():
        user.set_password(userForm.password.data)
        db.session.commit()
        flash('Your account has been updated.', 'success')
        return redirect(url_for('settings'))

    return render_template('user_settings.html', userForm=userForm, configForm=configForm)
def verifySettings():
    user = User.query.get_or_404(current_user.id)
    exist_mail = MailConfig.query.filter_by(uid=current_user.id).first()
    userForm = UserPasswordForm()
    if(exist_mail is None):
        return False
    if(exist_mail.incomingHost is None or exist_mail.outgoingHost is None or exist_mail.incomingPort is None or exist_mail.outgoingPort is None or exist_mail.account is None or exist_mail.get_password(exist_mail.account) is None):
        return False
    else:
        return True

#email configuration
@app.route('/emailConfig', methods=['POST'])
@login_required
def emailConfig():
    userForm = UserPasswordForm()
    configForm = EmailConfigForm()

    if configForm.validate_on_submit():
        mail_config = MailConfig(uid=current_user.id, incomingHost=configForm.incoming_host.data, incomingPort=configForm.incoming_port.data, outgoingHost=configForm.outgoing_host.data,
            outgoingPort=configForm.outgoing_port.data, account=configForm.emailaccount.data)
        exist_mail = MailConfig.query.filter_by(uid=current_user.id).first()
        if exist_mail:
            db.session.merge(mail_config)
        else:
            db.session.add(mail_config)
        db.session.commit()
        if(len(configForm.emailaccount.data)>0 and len(configForm.emailpassword.data)>0):
            mail_config.set_password(configForm.emailaccount.data, configForm.emailpassword.data)
        try:
            exist_mail = MailConfig.query.filter_by(uid=current_user.id).first()
            mail_list = [] 
            mail = imaplib.IMAP4_SSL(exist_mail.incomingHost,int(exist_mail.incomingPort))
            mail.login(exist_mail.account, exist_mail.get_password(exist_mail.account))
            flash('Connection Successful! Your email settings have been updated.', 'success')
        except mail.error as e:
            if 'Invalid credentials' in str(e):
                flash("Mail Server Connection Error: It seems that password was incorrect.", "warning")
            else:
                flash("Mail Server Connection Error: Please verify your email settings.", "warning")
                raise
        return redirect(url_for('settings'))

    return render_template('user_settings.html', userForm = userForm, configForm=configForm)

#send email
@app.route("/send",methods=["POST"])
@login_required
def sendmail():
    user = User.query.get_or_404(current_user.id)
    exist_mail = MailConfig.query.filter_by(uid=current_user.id).first()
    subject = "Re: "
    body = request.form["emailArea"]
    sender_email = exist_mail.account
    receiver_email = request.form["To"]
    password = exist_mail.get_password(exist_mail.account)

    message = MIMEMultipart("alternative")
    message["From"] = formataddr((str(Header(user.name, 'utf-8')), exist_mail.account))
    message["To"] = request.form["To"]
    message["Subject"] = request.form["Subject"]
    file = request.files['file']

    message.attach(MIMEText(body, "html"))

    file_to_send = MIMEApplication(file.stream.read())
    file_to_send.add_header('Content-Disposition', 'attachment', filename=file.filename)
    message.attach(file_to_send)

    text = message.as_string()

    context = ssl.create_default_context()
    with smtplib.SMTP_SSL(exist_mail.outgoingHost, exist_mail.outgoingPort, context=context) as server:
        server.login(sender_email, password)
        server.sendmail(sender_email, receiver_email, text)
    flash('Message Sent!', 'success')
    return redirect(url_for('inbox'))

#get email list, get email message
@login_required
def getemaillist(search = None):
    global global_mail_list
    global global_search_list
    exist_mail = MailConfig.query.filter_by(uid=current_user.id).first()
    mail_list = [] 
    mail = imaplib.IMAP4_SSL(exist_mail.incomingHost,int(exist_mail.incomingPort))
    mail.login(exist_mail.account, exist_mail.get_password(exist_mail.account))
    mail.list()
    mail.select('inbox')
    result, data = mail.uid('search', None, 'ALL') # (ALL/UNSEEN)
    for x in data[0].split()[0:100]:
        email_uid = x
        result, email_data = mail.uid('fetch',x, '(RFC822)')
        raw_email = email_data[0][1]
        #raw_email_string = raw_email.decode('utf-8')
        email_message = email.message_from_bytes(raw_email)
        date_tuple = email.utils.parsedate_tz(email_message['Date'])
        if date_tuple:
            local_date = datetime.datetime.fromtimestamp(email.utils.mktime_tz(date_tuple))
            local_message_date = "%s" %(str(local_date.strftime("%a, %m/%d/%Y, %H:%M %p")))
        realname, addr = email.utils.parseaddr(email_message['from'])
        email_to = str(email_message['To'])
        subject = str(email_message['Subject'])
        if(search is not None):
            if search.lower() in subject.lower() or search.lower() in email_to.lower() or search.lower() in realname.lower() or search.lower() in addr.lower():
                mail_item = {"uid": (email_uid).decode("ascii"), "email_from_name":realname,"email_from_addr":addr, "email_to": email_to, "subject": subject, "date":local_message_date}
                mail_list.append(mail_item)
        else:
            mail_item = {"uid": (email_uid).decode("ascii"), "email_from_name":realname,"email_from_addr":addr, "email_to": email_to, "subject": subject, "date":local_message_date}
            mail_list.append(mail_item)
    else:
        if(search):
            global_search_list = sorted(mail_list, key = lambda i: int(i['uid']), reverse=True)
        else:
            global_mail_list = sorted(mail_list, key = lambda i: int(i['uid']), reverse=True)
    mail.logout()

def getMessage(m = None):
    if m is not None:
        mail_list = []
        filename = None
        exist_mail = MailConfig.query.filter_by(uid=current_user.id).first()
        mail = imaplib.IMAP4_SSL(exist_mail.incomingHost)
        mail.login(exist_mail.account, exist_mail.get_password(exist_mail.account))
        mail.list()
        mail.select('inbox')
        result, email_data = mail.uid('fetch', m, '(RFC822)')
        raw_email = email_data[0][1]
        raw_email_string = raw_email.decode('utf-8')
        email_message = email.message_from_string(raw_email_string)
        for part in email_message.walk():
            if part.get_content_maintype() == 'multipart':
                continue
            if part.get('Content-Disposition') is None:
                continue
            filename = part.get_filename()
            #if decode_header(filename)[0][1] is not None:
            att_path = os.path.join('attachments', filename)
            if not os.path.isfile(att_path):
                try:
                    fp = open(att_path, 'wb')
                    fp.write(part.get_payload(decode=True))
                    fp.close()
                except FileNotFoundError:
                    continue
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
            h.ignore_links = False
            output = (h.handle(f'''{html}''').replace("\\r\\n", ""))
            output = output.replace("'", "")
            body = (output).encode('utf8', 'replace')
        realname, addr = email.utils.parseaddr(email_message['from'])
        email_to = str(email_message['To'])
        subject = str(email_message['Subject'])
        date_tuple = email.utils.parsedate_tz(email_message['Date'])
        if date_tuple:
            local_date = datetime.datetime.fromtimestamp(email.utils.mktime_tz(date_tuple))
            local_message_date = "%s" %(str(local_date.strftime("%a, %m/%d/%Y, %H:%M %p")))
        mail_message = {"uid": m, "email_from_name":realname,"email_from_addr":addr, "email_to": email_to, "subject": subject,
         "date":local_message_date,"body":body.decode(), "attachments":filename}
        mail_list.append(mail_message)
        mail.logout()
        return (mail_list)
    else:
        return ("")
#inbox 
@app.route("/inbox")
@app.route("/inbox/<idname>")
@login_required
def inbox(idname = None):
    return render_template('inbox.html', reply = None, activemessage = idname, data=global_mail_list, email_body = getMessage(idname))

#inboc reply and forward
@app.route("/inbox/<idname>/reply")
@app.route("/inbox/<idname>/forward")
@login_required
def reply(idname = None):
    return render_template('inbox.html', reply = idname, activemessage = None, data=global_mail_list, email_body = getMessage(idname))

#inbox new message
@app.route("/inbox/compose")
@login_required
def compose():
    return render_template('inbox.html', reply = None, activemessage = None, data=global_mail_list, compose=True)

#inbox check for mail
@app.route("/inbox/sync")
@login_required
def syncmail():
    if(verifySettings()):
        getemaillist(None)
        return render_template('inbox.html', reply = None, activemessage = None, data=global_mail_list, email_body = None)
    else:
        flash('You need to add your email account settings.', 'warning')
        return redirect(url_for('settings'))

#inbox search starter (needs improved)
@app.route("/inbox/search", methods=['POST'])
@login_required
def searchmail():
    search = request.form['mail_search']
    getemaillist(search)
    return render_template('inbox.html', reply = None, activemessage = None, data=global_search_list, email_body = None)

#inbox delete message
@app.route("/inbox/<id>/delete")
@login_required
def delete(id = None):
    if id is not None:
        exist_mail = MailConfig.query.filter_by(uid=current_user.id).first()
        mail = imaplib.IMAP4_SSL(exist_mail.incomingHost)
        mail.login(exist_mail.account, exist_mail.get_password(exist_mail.account))
        mail.list()
        mail.select('inbox')
        result, email_data = mail.uid('fetch', id, '(RFC822)')
        mail.uid('STORE',id,'+X-GM-LABELS', '\\Trash')
        mail.expunge()
        mail.close()
        mail.logout()
        getemaillist(None)
        flash(email_data,'success')
        return render_template('inbox.html', reply = None, activemessage = None, data=global_mail_list, email_body = None)

#inbox download attachment
@app.route('/attachments/<path:filename>')
def getFile(filename):
    try:
        return send_from_directory('attachments', filename, as_attachment=True)
    except FileNotFoundError:
        abort(404)

#user management
@app.route('/user_manage')
@requires_access_level(ACCESS['admin'])
def user_manage():
    all_users = User.query.all()
    return render_template('user_manage.html', users=all_users)

# user details & update
@app.route('/user_detail/<int:user_id>', methods=['GET','POST'])
@requires_access_level(ACCESS['admin'])
def user_detail(user_id):
    user = User.query.get_or_404(user_id)
    form = UserDetailForm()
    form.id.data = user.id
    form.name.data = user.name
    form.email.data = user.email
    form.username.data = user.username
    form.access.data = user.access
    return render_template('user_detail.html', form=form)

# update user
@app.route('/update_user/<int:user_id>', methods=['POST'])
@requires_access_level(ACCESS['admin'])
def update_user(user_id):
    user = User.query.get_or_404(user_id)
    form = UserDetailForm()

    db_user = user.username 

    if form.validate_on_submit():
        user.name = form.name.data
        user.email = form.email.data

        new_user = form.username.data

        if new_user != db_user: 
            valid_user = User.query.filter_by(username=new_user).first() 
            if valid_user is not None:
                flash("Username is already taken.", 'danger')
                return redirect(url_for('user_manage'))
        user.username = form.username.data
        user.access = request.form['access_lvl']
        db.session.commit()
        flash('The user has been updated.', 'success')
        return redirect(url_for('user_manage'))

    return redirect(url_for('user_manage'))

# delete user
@app.route('/delete_user/<int:user_id>', methods=['POST'])
@requires_access_level(ACCESS['admin'])
def delete_user(user_id):
    if request.method == 'POST': #if it's a POST request, delete the friend from the database
        user = User.query.get_or_404(user_id)
        db.session.delete(user)
        db.session.commit()
        flash('User has been deleted.', 'success')
        return redirect(url_for('user_manage'))

    return redirect(url_for('user_manage'))

# new user
@app.route('/new_user', methods=['GET', 'POST'])
def new_user():
    form = NewUserForm()

    if request.method == 'POST' and form.validate_on_submit():
        user = User(name=form.name.data, username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        user.access = request.form['access_lvl']
        db.session.add(user)
        db.session.commit()
        flash('User has been successfully created.', 'success')
        return redirect(url_for('login'))

    return render_template('new_user.html',  pageTitle='New User | dogPile Email Client', form=form)

#tests

def test_new_user_registration():
    #TEST CREATING AND DELETING A USER
    user = User(name='MSE Dummy User',username='dummyuser',email='dummyuser@gmail.com',access=ACCESS['user'])
    user.set_password('testing')
    db.session.add(user)
    db.session.commit()
    User.query.filter_by(email='dummyuser@gmail.com').delete()
    db.session.commit()
    assert db.session
def test_index():
    with app.test_client() as test_client:
        response = test_client.get('/')
        assert response.status_code == 200
def test_inbox_unauthenticated():
    with app.test_client() as test_client:
        response = test_client.get('/inbox')
        assert response.status_code == 302
def test_inbox_authenticated():
    with app.test_client() as test_client:
        response = test_client.get('/inbox')
        assert response.status_code == 302
def test_user_settings_unauthenticated():
    with app.test_client() as test_client:
        response = test_client.get('/settings')
        assert response.status_code == 302
def test_user_settings_authenticated():
    with app.test_client() as test_client:
        response = test_client.get('/settings')
        assert response.status_code == 302
def test_email_config_unauthenticated_post():
    with app.test_client() as test_client:
        response = test_client.post('/emailConfig')
        assert response.status_code == 302
def test_email_config_authenticated_post():
    with app.test_client() as test_client:
        response = test_client.post('/emailConfig')
        assert response.status_code == 302
	
if __name__ == '__main__':
    app.run(debug=False)
