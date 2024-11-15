from flask import Flask, request, jsonify, render_template, redirect, url_for, flash, session
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
    poll_type = db.Column(db.String(50), nullable=False)  # 'multiple_choice' or 'suggestion'
    is_active = db.Column(db.Boolean, default=True)
    
    # Changed the backref to 'poll_options' to avoid conflict with 'options' on Poll
    options = db.relationship('PollOption', backref='poll_ref', lazy=True) 

class PollOption(db.Model):
    __tablename__ = 'poll_options'
    id = db.Column(db.Integer, primary_key=True)
    poll_id = db.Column(db.Integer, db.ForeignKey('polls.id'), nullable=False)
    option_text = db.Column(db.String(255), nullable=False)
    
    # This relationship links PollOption to Poll via 'poll_id'
    # Here the 'poll_ref' backref is used, which avoids conflict with 'options' on Poll.
    poll = db.relationship('Poll', backref=db.backref('poll_options', lazy=True))  

class Vote(db.Model):
    __tablename__ = 'votes'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    poll_id = db.Column(db.Integer, db.ForeignKey('polls.id'), nullable=False)
    option_id = db.Column(db.Integer, db.ForeignKey('poll_options.id'))  # For multiple-choice
    response = db.Column(db.String(255))  # For suggestion-type polls


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
            session['user_id'] = user.id  # Store user ID in session
            flash("Login successful!", 'success')
            return redirect(url_for('polls_page'))  # Redirect to the polls page after login

        flash("Invalid credentials. Please try again.", 'danger')
        return redirect(url_for('login'))

    return render_template('login.html')


@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password) and user.is_admin:
            session['user_id'] = user.id  # Store user ID in session
            flash("Login successful!", 'success')
            return redirect(url_for('admin_dashboard'))  # Redirect to the admin dashboard

        flash("Invalid credentials or you are not an admin.", 'danger')
        return redirect(url_for('admin_login'))

    return render_template('admin_login.html')


@app.route('/admin_dashboard')
def admin_dashboard():
    user_id = session.get('user_id')
    user = User.query.get(user_id)

    if not user or not user.is_admin:
        flash("You are not authorized to view this page.", 'danger')
        return redirect(url_for('home'))

    # Query all polls to display
    polls = Poll.query.all()

    return render_template('admin_dashboard.html', polls=polls)

@app.route('/create_poll', methods=['GET', 'POST'])
def create_poll():
    user_id = session.get('user_id')
    user = User.query.get(user_id)

    if not user or not user.is_admin:
        flash("You are not authorized to create polls.", 'danger')
        return redirect(url_for('polls_page'))

    if request.method == 'POST':
        question = request.form.get('question')
        poll_type = request.form.get('poll_type')

        # Validate that a question was provided
        if not question:
            flash("Poll question cannot be empty.", 'danger')
            return redirect(url_for('create_poll'))

        poll = Poll(question=question, poll_type=poll_type)
        db.session.add(poll)
        db.session.commit()  # Save the poll first to get poll_id

        if poll_type == 'multiple_choice':
            options = []
            option_count = 1
            while True:
                option_text = request.form.get(f'option_{option_count}')
                if option_text:
                    options.append(PollOption(poll_id=poll.id, option_text=option_text))
                    option_count += 1
                else:
                    break  # Stop when no more options are found in the form

            # Ensure there are at least 2 options
            if len(options) < 2:
                flash("You must provide at least two options for a multiple-choice poll.", 'danger')
                db.session.delete(poll)  # Rollback the poll creation
                db.session.commit()
                return redirect(url_for('create_poll'))

            db.session.add_all(options)
            db.session.commit()

        flash("Poll created successfully!", 'success')
        return redirect(url_for('admin_dashboard'))

    return render_template('create_poll.html')


@app.route('/polls')
def polls_page():
    polls = Poll.query.filter_by(is_active=True).all()
    return render_template('polls.html', polls=polls)


@app.route('/vote/<int:poll_id>', methods=['POST'])
def vote(poll_id):
    user_id = session.get('user_id')
    user = User.query.get(user_id)

    if not user:
        return jsonify(message="User not found"), 404

    poll = Poll.query.get(poll_id)
    if not poll:
        return jsonify(message="Poll not found"), 404

    if poll.poll_type == 'multiple_choice':
        option_id = request.form.get('choice')
        if not option_id:
            return jsonify(message="Please select an option."), 400

        option = PollOption.query.get(option_id)
        if not option or option.poll_id != poll_id:
            return jsonify(message="Invalid option selected."), 400

        existing_vote = Vote.query.filter_by(user_id=user.id, poll_id=poll.id).first()
        if existing_vote:
            return jsonify(message="You have already voted on this poll."), 403

        vote = Vote(user_id=user.id, poll_id=poll.id, option_id=option.id)
        db.session.add(vote)
        db.session.commit()

        return jsonify(message="Vote successfully casted."), 200

    elif poll.poll_type == 'suggestion':
        response = request.form.get('response')
        if not response:
            return jsonify(message="Please provide a suggestion."), 400

        existing_vote = Vote.query.filter_by(user_id=user.id, poll_id=poll.id).first()
        if existing_vote:
            return jsonify(message="You have already voted on this poll."), 403

        vote = Vote(user_id=user.id, poll_id=poll.id, response=response)
        db.session.add(vote)
        db.session.commit()

        return jsonify(message="Suggestion submitted successfully."), 200

    return jsonify(message="Poll type not supported."), 400


if __name__ == '__main__':
    app.run(debug=True)