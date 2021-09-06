from flask import Flask, request, render_template, redirect, session, jsonify, json, send_from_directory
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

app = Flask(__name__,static_url_path='/static')

imap_host = ''
imap_user = ''
imap_pass = ''

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

@app.route('/attachments/<path:filename>')
def getFile(filename):
    try:
        return send_from_directory('attachments', filename, as_attachment=True)
    except FileNotFoundError:
        abort(404)

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        userEmail = request.form['email'] 
        userPassword = request.form['password']
        userConfig = open("userConfig.txt", 'w')
        userConfig.write(userEmail + "\n"+userPassword)
        userConfig.close()

        if userAuth():
            return redirect('/inbox')  
        else:
            return redirect('/')
    else:
        if userAuth() == False:
            return render_template('login.html')
        else:
            return redirect('inbox')

@app.route('/logout')
def logout():
    file = open('userConfig.txt', 'r+')
    file.truncate(0)
    file.close()
    return redirect('/')

@app.route('/config', methods=['POST'])
def config():
    if request.method == 'POST':
        host = request.form['host'] 
        port = request.form['port']
        protocol = request.form.get('protocol')
        configFile = open("emailConfig.txt", 'w')
        configFile.write(host + "\n"+port+"\n"+protocol)
        configFile.close()
        return redirect('/inbox')

@app.route("/inbox")
@app.route("/inbox/<idname>")

def home(idname = None):
    if userAuth() == False:
        return redirect("/")
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

# create schedule for printing time
scheduler = BackgroundScheduler()
scheduler.start()
scheduler.add_job(
    func=getemaillist,
    trigger=IntervalTrigger(seconds=30),
    id='get mail every 60 seconds',
    name='get mail every 60 seconds',
    replace_existing=True)
# Shut down the scheduler when exiting the app
atexit.register(lambda: scheduler.shutdown())

getemaillist()