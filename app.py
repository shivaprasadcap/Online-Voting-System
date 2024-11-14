from flask import Flask, request, jsonify, render_template, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from datetime import timedelta

# Initialize Flask app and configurations
app = Flask(__name__)

# Database Configuration and App Settings
app.config['SQLALCHEMY_DATABASE_URI'] = 'mssql+pyodbc://@LIN81001940\\SQLEXPRESS/VotingDb?driver=ODBC+Driver+17+for+SQL+Server&trusted_connection=yes'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'a3f85d07a258d4b6f98d559634d1d2c8c0a78d5a7f8b3fa3d8eb7cdb5929baf4'  # Required for session management and flash messages

# Initialize Extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

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

# Routes

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        data = request.form
        existing_user = User.query.filter_by(username=data['username']).first()

        if existing_user:
            flash("Username already exists. Please choose another.", 'danger')
            return render_template('register.html')

        user = User(username=data['username'])
        user.set_password(data['password'])
        db.session.add(user)
        db.session.commit()

        flash("User registered successfully!", 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            # No JWT token needed here anymore, we can just redirect
            flash("Login successful!", 'success')
            return redirect(url_for('polls_page'))  # Redirect to the polls page after login

        flash("Invalid credentials. Please try again.", 'danger')
        return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/polls')
def polls_page():
    # Since we are no longer using JWT, we simply assume the user is logged in and proceed
    # In a real-world scenario, you would use sessions or some other way to identify the user.
    # For now, let's just return the polls directly.
    
    polls = Poll.query.filter_by(is_active=True).all()
    return render_template('polls.html', polls=polls)

@app.route('/vote/<int:poll_id>', methods=['POST'])
def vote(poll_id):
    # We assume the user is logged in, but in this simplified version, there's no actual authentication
    # You may want to add logic to handle users' votes based on the session or username.
    
    # For now, let’s proceed with the assumption that a valid user is logged in (perhaps via a session).
    
    user = User.query.first()  # In a real case, you would identify the logged-in user from the session or cookies.

    if not user:
        return jsonify(message="User not found"), 404

    if Vote.query.filter_by(user_id=user.id, poll_id=poll_id).first():
        return jsonify(message="You have already voted on this poll."), 403

    poll = Poll.query.get(poll_id)
    if not poll:
        return jsonify(message="Poll not found"), 404

    vote = Vote(user_id=user.id, poll_id=poll.id)
    db.session.add(vote)
    db.session.commit()

    return jsonify(message="Vote successfully casted."), 200

if __name__ == '__main__':
    app.run(debug=True)
