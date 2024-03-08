from flask import Flask, render_template, request
import mariadb
import json
import bcrypt
import jwt
import time

host = "127.0.0.1"
port = 3306
responseCode = 0

conn = mariadb.connect(
    host = host,
    port = port,
    username = 'root',
    password = 'task',
    database = 'sistem_za_teretanu'
)

curr = conn.cursor()

def auth(token, user):
    try:
        payload = jwt.decode(token, key=app.config['SECRET_KEY'],algorithms=['HS256'])
    except jwt.ExpiredSignatureError as expiredError:
        return False
    except:
        return False
    if payload['username'] == user:
        return True

def checkHash(password: str, passwordHash: str) -> bool:
  passwordBytes = password.encode("utf-8")
  result = bcrypt.checkpw(passwordBytes, passwordHash.encode("utf-8"))
  return result

app = Flask(__name__, template_folder="templates/")
app.config['SECRET_KEY'] = "panklav"
exptime = 300*600

@app.route("/")
def index():

    return json.dumps({"responseCode" : 0, "message" : "Jak signal"})

@app.route('/new_member', methods=['POST', 'GET'])
def newMember():

    if 'token' not in request.json:

        return json.dumps({'responseCode' : 0, 'message' : 'JWT Error'})
    
    if 'username' not in request.json  or 'password' not in request.json:

        return json.dumps({'responseCode' : 0, 'message' : 'Username ili Password nisu uneti!'})

    data = json.loads(request.data)
    token = data.get('token')

    payload = jwt.decode(token, key=app.config['SECRET_KEY'],algorithms=['HS256'])

    username = payload['username']

    print(payload)
    
    if auth(token, username) == False:

        return json.dumps({'responseCode' : -1, 'message' : 'Auth Error'})
    
    getSQL = 'SELECT role FROM users WHERE username = ?'
    curr.execute(getSQL, [username])
    roleInput = curr.fetchone()[0]
    conn.commit()
    
    if roleInput != 'admin':

        return json.dumps({'responseCode' : -1, 'messege' : 'Nisi admin!'})

    username = data.get('username')
    password = data.get('password')
    role = 'member'
    membership = 20

    getSQL = "SELECT id FROM users WHERE username = ?"
    curr.execute(getSQL, [username])
    idInput = curr.fetchone()

    if idInput != None:

        return json.dumps({'responseCode' : -1, 'messege' : 'ID Error'})
    
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    postSQL = "INSERT INTO users(username, password, role, membership) VALUES(?, ?, ?, ?)"
    curr.execute(postSQL, [username, hashed, role, membership])
    conn.commit()

    return json.dumps({"responseCode" : 0, "message" : "Clan dodat!"})


@app.route('/login', methods = ['GET', 'POST'])
def login():

    if "username" not in request.json or "password" not in request.json:

        return json.dumps({'responseCode' : -1, 'messege' : 'Username or Password Error'})
    
    data = json.loads(request.data)
    username = data.get('loginUsername')
    password = data.get('loginPassword')
    

    getSQL = "SELECT password FROM users WHERE username = ?"
    curr.execute(getSQL, [username])
    passwordInput = curr.fetchone()[0]
    conn.commit()

    if checkHash(password, passwordInput) == False:

        return json.dumps({'responseCode' : -1, 'messege' : 'CheckHash Error'})
    
    payload = {
        "username": username,
        "exp": int(time.time()) + exptime
    }
    token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

    print(token)
    
    return json.dumps({'responseCode' : 0, 'messege' : 'Ulogovao si se!'})

@app.route('/extend', methods = ['GET', 'POST'])
def extender():

    if 'token' not in request.json:

        return json.dumps({'responseCode' : 0, 'message' : 'JWT Error'})
    
    if 'extend' not in request.json:

        return json.dumps({'responseCode' : -1, 'messege' : 'Nisi uneo extend!'})
        
    if 'extendUser' not in request.json:

        return json.dumps({'responseCode' : -1, 'messege' : 'Nisi uneo user-a!'})
    
    data = json.loads(request.data)
    token = data.get('token')

    payload = jwt.decode(token, key=app.config['SECRET_KEY'],algorithms=['HS256'])

    username = payload['username']

    print(payload)
    
    if auth(token, username) == False:

        return json.dumps({'responseCode' : -1, 'message' : 'Auth Error'})
    
    getSQL = 'SELECT role FROM users WHERE username = ?'
    curr.execute(getSQL, [username])
    roleInput = curr.fetchone()[0]
    conn.commit()
    
    if roleInput != 'admin':

        return json.dumps({'responseCode' : -1, 'messege' : 'Nisi admin!'})
    
    extendSQL = "UPDATE users SET membership = membership + ? WHERE username = ?"
    username = data.get('extendUser')
    extend = data.get('extend')
    curr.execute(extendSQL, [extend, username])
    conn.commit()

    return json.dumps({'responseCode' : 0, 'messege' : 'Clanarina produzena.'})

@app.route('/change', methods = ['GET', 'POST'])
def change():

    if 'token' not in request.json:

        return json.dumps({'responseCode' : 0, 'message' : 'JWT Error'})
    
    if 'changeUser' not in request.json or 'changePass' not in request.json:

        return json.dumps({'responseCode' : -1, 'messege' : 'Nisi uneo Username ili Password!'})

    data = json.loads(request.data)
    token = data.get('token')

    payload = jwt.decode(token, key=app.config['SECRET_KEY'],algorithms=['HS256'])

    username = payload['username']

    print(payload)
    
    if auth(token, username) == False:

        return json.dumps({'responseCode' : -1, 'message' : 'Auth Error'})
    
    getSQL = 'SELECT role FROM users WHERE username = ?'
    curr.execute(getSQL, [username])
    roleInput = curr.fetchone()[0]
    conn.commit()
    
    if roleInput != 'admin':

        return json.dumps({'responseCode' : -1, 'messege' : 'Nisi admin!'})
    
    username = data.get('changeUser')
    changePass = data.get('changePass')

    hashed = bcrypt.hashpw(changePass.encode('utf-8'), bcrypt.gensalt())

    changeSQL = "UPDATE users SET password = ? WHERE username = ?"
    curr.execute(changeSQL, [hashed, username])
    conn.commit()

    return json.dumps({'responseCode' : 0, 'messege' : 'Password promenjen!'})

@app.route('/add', methods=['POST', 'GET'])
def addMember():

    if 'token' not in request.json:

        return json.dumps({'responseCode' : 0, 'message' : 'JWT Error'})
    
    if 'addUser' not in request.json or 'addPass' not in request.json:

        return json.dumps({'responseCode' : -1, 'messege' : 'Nisi uneo Username ili Password!'})
    
    if 'membership' not in request.json:

        return json.dumps({'responseCode' : -1, 'messege' : 'Membership Error'})

    data = json.loads(request.data)
    token = data.get('token')

    payload = jwt.decode(token, key=app.config['SECRET_KEY'],algorithms=['HS256'])

    username = payload['username']

    print(payload)
    
    if auth(token, username) == False:

        return json.dumps({'responseCode' : -1, 'message' : 'Auth Error'})
    
    getSQL = 'SELECT role FROM users WHERE username = ?'
    curr.execute(getSQL, [username])
    roleInput = curr.fetchone()[0]
    conn.commit()
    
    if roleInput != 'admin':

        return json.dumps({'responseCode' : -1, 'messege' : 'Nisi admin!'})
    
    if role != 'member':

        return json.dumps({'responseCode' : -1, 'messege' : 'Member Error'})
    
    username = data.get('addUser')
    password = data.get('addPass')
    role = data.get('role')
    membership = data.get('membership')

    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    postSQL = "INSERT INTO users(username, password, role, membership) VALUES(?, ?, ?, ?)"
    curr.execute(postSQL, [username, hashed, role, membership])
    conn.commit()

    return json.dumps({"responseCode" : 0, "message" : "Success"})

@app.route('/view', methods = ['GET', 'POST'])
def view():

    if 'token' not in request.json:

        return json.dumps({'responseCode' : 0, 'message' : 'JWT Error'})

    data = json.loads(request.data)
    token = data.get('token')

    payload = jwt.decode(token, key=app.config['SECRET_KEY'],algorithms=['HS256'])

    username = payload['username']

    print(payload)
    
    if auth(token, username) == False:

        return json.dumps({'responseCode' : -1, 'message' : 'Auth Error'})
    
    getSQL = 'SELECT role FROM users WHERE username = ?'
    curr.execute(getSQL, [username])
    roleInput = curr.fetchone()[0]
    conn.commit()
    
    if roleInput != 'member':

        return json.dumps({'responseCode' : -1, 'messege' : 'Nisi admin!'})
    
    viewSQL = 'SELECT membership FROM users WHERE username = ?'
    curr.execute(viewSQL, [username])
    membership = curr.fetchone()[0]
    conn.commit()

    return json.dumps({'responseCode' : 0, 'message' : f'Imas jos {membership} dana clanarine!'})

@app.route('/register', methods=['POST', 'GET'])
def register():
    if 'username' not in request.json  or 'password' not in request.json:

        return json.dumps({'responseCode' : 0, 'message' : 'Username or Password Error'})

    data = json.loads(request.data)
    username = data.get('loginUsername')
    password = data.get('loginPassword')
    role = 'admin'


    getSQL = "SELECT id FROM users WHERE username = ?"
    curr.execute(getSQL, [username])
    idInput = curr.fetchone()

    if idInput != None:

        return json.dumps({'responseCode' : -1, 'messege' : 'ID Error'})
    
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    postSQL = "INSERT INTO users(username, password, role) VALUES(?, ?, ?)"
    curr.execute(postSQL, [username, hashed, role])
    conn.commit()

    print("Uspesno")
    return json.dumps({"responseCode" : 0, "message" : "Success"})


if(__name__ == "__main__"):
    app.run(host = host, port = 9190, debug = True)