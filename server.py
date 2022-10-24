from flask import Flask, jsonify, request
from waitress import serve

import generate
import pwned

app = Flask(__name__)

@app.route("/", methods=['GET'])
def home():
    return "Hello World"

@app.route("/is-pwned", methods=['POST'])
def isPwned():
    if(request.method == 'POST'):
        user_password = request.get_json(force=True)
        res = pwned.main(user_password['check'])
        return res, 200
    else:
        return jsonify({"message": "No data"}), 404

@app.route("/generate-safe", methods=['POST'])
def generateSafe():
        options = request.get_json()
        length = options['length']
        include_lowercase = options['include_lowercase']
        include_uppercase = options['include_uppercase']
        include_digit = options['include_digit']
        include_symbol = options['include_symbol']
        respo = generate.generateSafePassword(length, include_lowercase,include_uppercase,include_digit,include_symbol)
        return respo, 200

if __name__ == "__main__":
    print("Server running on port 5000...")
    serve(app, host="0.0.0.0", port=5000)
