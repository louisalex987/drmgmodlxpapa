from flask import jsonify

def success(payload, status=200):
    return jsonify(payload), status

def error(message, status=400):
    return jsonify({"error": message}), status