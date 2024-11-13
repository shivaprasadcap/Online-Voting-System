from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from datetime import timedelta
from flask_cors import CORS
import pyodbc

# Initialize Flask app and configurations
app = Flask(__name__)

# Enable CORS for React app (adjust to your frontend URL if needed)
CORS(app)

# Database Configuration and App Settings
app.config['SQLALCHEMY_DATABASE_URI'] = 'mssql+pyodbc://@LIN81001940\\SQLEXPRESS/VotingDb?driver=ODBC+Driver+17+for+SQL+Server&trusted_connection=yes'
app.config['JWT_SECRET_KEY'] = 'your_secret_key_here'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'your_secret_key_here'

# Initialize Extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# Models
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    voted_polls = db.relationship('Vote', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

class Poll(db.Model):
    __tablename__ = 'polls'
    id = db.Column(db.Integer, primary_key=True)
    question = db.Column(db.String(255), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    votes = db.relationship('Vote', backref='poll', lazy=True)

class Vote(db.Model):
    __tablename__ = 'votes'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    poll_id = db.Column(db.Integer, db.ForeignKey('polls.id'), nullable=False)

# Routes (Flask API)

# User Registration
@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    existing_user = User.query.filter_by(username=data['username']).first()
    if existing_user:
        return jsonify({"message": "Username already exists."}), 400

    user = User(username=data['username'])
    user.set_password(data['password'])
    db.session.add(user)
    db.session.commit()

    return jsonify({"message": "User registered successfully!"}), 201

# User Login
@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    username = data['username']
    password = data['password']

    user = User.query.filter_by(username=username).first()
    if user and user.check_password(password):
        access_token = create_access_token(identity=user.id)
        return jsonify(access_token=access_token), 200

    return jsonify({"message": "Invalid credentials"}), 401

# Fetch Active Polls
@app.route('/api/polls', methods=['GET'])
@jwt_required()
def polls_page():
    current_user_id = get_jwt_identity()
    polls = Poll.query.filter_by(is_active=True).all()
    return jsonify([{'id': poll.id, 'question': poll.question} for poll in polls])

# Vote on a Poll
@app.route('/api/vote/<int:poll_id>', methods=['POST'])
@jwt_required()
def vote(poll_id):
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    if Vote.query.filter_by(user_id=user.id, poll_id=poll_id).first():
        return jsonify({"message": "You have already voted on this poll."}), 400

    poll = Poll.query.get(poll_id)
    if not poll:
        return jsonify({"message": "Poll not found."}), 404

    vote = Vote(user_id=user.id, poll_id=poll.id)
    db.session.add(vote)
    db.session.commit()

    return jsonify({"message": "Vote successfully casted."}), 200

if __name__ == '__main__':
    app.run(debug=True)
