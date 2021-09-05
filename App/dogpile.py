from flask import Flask, request, render_template, redirect, session, jsonify, json
import datetime

app = Flask(__name__,static_url_path='/static')

@app.template_filter()
def datetimefilter(value, format='%Y/%m/%d %H:%M'):
    return value.strftime(format)
app.jinja_env.filters['datetimefilter'] = datetimefilter

def getemaillist():
  data = [
             {"id":"1","name": "John", "email": "john@test.com", "subject":"We are trying to reach you about your warranty", "date": datetime.datetime.now().strftime("%m/%d/%Y, %H:%M %p")},
              {"id":"2","name": "Jenny", "email": "jenny@yahoo.com", "subject":"Can we just be friends?", "date": datetime.datetime.now().strftime("%m/%d/%Y, %H:%M %p")},
              {"id":"3","name": "Amanda", "email": "amanda@test.com", "subject":"Re: Going back to school", "date": datetime.datetime.now().strftime("%m/%d/%Y, %H:%M %p")},
              {"id":"4","name": "Matt", "email": "matt@test.com", "subject":"Data Request", "date": datetime.datetime.now().strftime("%m/%d/%Y, %H:%M %p")},
              {"id":"5","name": "Jacob", "email": "jacob@test.com", "subject":"Want to go to lunch?", "date": datetime.datetime.now().strftime("%m/%d/%Y, %H:%M %p")},
              {"id":"6","name": "Morgan", "email": "morgan@test.com", "subject":"Let us revolt against the boss!", "date": datetime.datetime.now().strftime("%m/%d/%Y, %H:%M %p")},
              {"id":"7","name": "Dusty", "email": "dusty@test.com", "subject":"Re: Let us revolt against the boss!", "date": datetime.datetime.now().strftime("%m/%d/%Y, %H:%M %p")},
              {"id":"8","name": "Carol", "email": "carol@test.com", "subject":"Here is my credit card info, as you requested", "date": datetime.datetime.now().strftime("%m/%d/%Y, %H:%M %p")},
              
           ]
  return (data)
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
    
    return render_template('_inbox.html', reply = None, activemessage = idname, data=getemaillist(), email_body = message(idname), config = getConfig())
def message(fname):
  if fname is None:
    return "No Mail!"
  if fname:
    return """<p>Lorem ipsum dolor sit amet consectetur adipiscing elit sed do eiusmod tempor incididunt ut labore et dolore.</p>
<p>Magna aliqua ut enim ad minim veniam quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat duis aute irure dolor in reprehenderit in.</p>
<p>Voluptate velit esse cillum dolore eu fugiat nulla pariatur excepteur sint occaecat cupidatat. Non proident sunt.</p>
<p>In culpa qui officia deserunt mollit anim id est laborum sed ut perspiciatis unde omnis iste natus error.</p>
<p>Sit voluptatem accusantium doloremque laudantium totam rem aperiam eaque ipsa quae ab illo inventore veritatis et quasi architecto beatae vitae. Dicta sunt explicabo.</p>"""

@app.route("/inbox/<idname>/reply")
@app.route("/inbox/<idname>/forward")

def homereply(idname = None):
    if userAuth() == False:
        return redirect("/")
    listdata = getemaillist()
    message = [x for x in listdata if x['id'] == idname]
    #return (json.dumps(message[0]))
    return render_template('_inbox.html', reply = idname, activemessage = None, data=listdata, email = message[0]["email"],email_body = messagereply(message[0]), config = getConfig())
def messagereply(mData):
  if mData is None:
    return "No Mail!"
  if mData:
    body = "Subject: " +mData["subject"]+"<br>"+"From: "+mData["email"]+"<br>"+"Date: "+mData["date"]+"<br>"
    body += """<p>Lorem ipsum dolor sit amet consectetur adipiscing elit sed do eiusmod tempor incididunt ut labore et dolore.</p>
<p>Magna aliqua ut enim ad minim veniam quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat duis aute irure dolor in reprehenderit in.</p>
<p>Voluptate velit esse cillum dolore eu fugiat nulla pariatur excepteur sint occaecat cupidatat. Non proident sunt.</p>
<p>In culpa qui officia deserunt mollit anim id est laborum sed ut perspiciatis unde omnis iste natus error.</p>
<p>Sit voluptatem accusantium doloremque laudantium totam rem aperiam eaque ipsa quae ab illo inventore veritatis et quasi architecto beatae vitae. Dicta sunt explicabo.</p>"""
    return (body)
@app.route("/send", methods=['POST'])
def send():
    formTo = request.form['To']
    formFrom = request.form['CC']
    formBody = request.form['emailArea']

    message = formTo + "<br>"
    message += formFrom + "<br>"
    message += formBody
    return (message)

