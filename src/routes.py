# routes.py

from flask import Blueprint, render_template, request, jsonify

# Define a Blueprint named 'main'
main = Blueprint('main', __name__)

# Define a route within this blueprint
@main.route('/')
def home():
    # Render an HTML template or return a response
    return render_template('index.html')

@main.route('/api/data', methods=['GET'])
def get_data():
    # Example API endpoint
    data = {"message": "Hello, world!"}
    return jsonify(data)
