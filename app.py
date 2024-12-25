# flask imports
from flask import Flask, render_template, request, url_for, redirect

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

@app.route("/createroom", methods=['POST'])
def create_room():
    check_user_key(request.remote_addr)
    if 'room_name' not in request.form:
        return "Bad request<br><a href='/'>Go back</a>"
    
    room_name = request.form['room_name']

    # check if room doesn't already exist
    if room_name not in rooms.keys():
        # create room
        rooms[room_name] = []
        return render_template("room.html", messages=[])
    else:
        return "Room already exists"
        
@app.route("/joinroom", methods=['POST'])
def join_room():
    check_user_key(request.remote_addr)
    if 'room_name' not in request.form:
        return "Bad request<br><a href='/'>Go back</a>"
    
    room_name = request.form['room_name']

    if room_name not in rooms.keys():
        return "Room does not exist<br><a href='/'>Go back</a>"
        
    return render_template("room.html", messages=rooms[room_name])

def check_user_key(ip_addr):
    if ip_addr not in private_keys.keys():
        private_keys[ip_addr] = rsa.generate_private_key(
            public_exponent=65537,
            key_size= 2 ** 13, # 2048 is 2 ^ 11
        )
    return private_keys[ip_addr]

app.run(debug=True, port=8000)