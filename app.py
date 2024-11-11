from flask import Flask, request, jsonify, render_template, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mssql+pyodbc://@LIN81001940\\SQLEXPRESS/VotingDb?driver=ODBC+Driver+17+for+SQL+Server&trusted_connection=yes'
app.config['JWT_SECRET_KEY'] = 'your_jwt_secret_key'
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

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

class Poll(db.Model):
    __tablename__ = 'polls'
    id = db.Column(db.Integer, primary_key=True)
    question = db.Column(db.String(255), nullable=False)
    is_active = db.Column(db.Boolean, default=True)

# Routes
@app.route('/')
def home():
    return render_template("home.html")  # Render the home page template

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Handle the form submission
        data = request.form
        existing_user = User.query.filter_by(username=data['username']).first()

        if existing_user:
            return render_template('register.html', message="Username already exists. Please choose another.")  # Show message if username exists

        user = User(username=data['username'])
        user.set_password(data['password'])
        db.session.add(user)
        db.session.commit()

        # After registration, show a success message
        return render_template('register.html', message="User registered successfully!")  # Show success message

    return render_template('register.html')  # Show the registration form

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Get the form data from the POST request
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            access_token = create_access_token(identity=user.id)
            return jsonify(access_token=access_token), 200
        return jsonify(message="Invalid credentials"), 401

    # If it's a GET request, render the login form
    return render_template('login.html')

@app.route('/create_poll', methods=['POST'])
@jwt_required()
def create_poll():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    if not user.is_admin:
        return jsonify(message="Admin privileges required"), 403

    data = request.json
    poll = Poll(question=data['question'])
    db.session.add(poll)
    db.session.commit()
    return jsonify(message="Poll created successfully"), 201

if __name__ == '__main__':
    app.run(debug=True)
