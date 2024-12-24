from flask import Flask

app = Flask(__name__)

rooms = []

@app.route("/")
def home():
    return "Home"

app.run(debug=True, port=8000)