# flask imports
from flask import Flask, render_template, request, url_for, session

# cryptography imports
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# flask app
app = Flask(__name__)

# storing current rooms and users' keys.
rooms = {}
private_keys = {}

@app.route("/")
def home():
    pub_key = check_user_key(request.remote_addr).public_key()
    pem = pub_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return render_template('index.html', pub_key=pem)

@app.route("/createroom")
def createroom():
    check_user_key(request.remote_addr)
    return "Create room"

@app.route("/joinroom", methods=['POST'])
def join_room():
    check_user_key(request.remote_addr)
    if 'room_id' not in request.form:
        return "Bad request<br><a href='/'>Go back</a>"
    if request.form['room_id'] not in rooms.keys():
        return "Room does not exist<br><a href='/'>Go back</a>"
        
    return request.form['room_id']

def check_user_key(ip_addr):
    if ip_addr not in private_keys.keys():
        private_keys[ip_addr] = rsa.generate_private_key(
            public_exponent=65537,
            key_size= 2 ** 13, # 2048 is 2 ^ 11
        )
    return private_keys[ip_addr]

app.run(debug=True, port=8000)