from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_pymongo import PyMongo
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "supersecretkey"

# MongoDB Configuration
mongo_uri = 'mongodb://localhost:27017'
db_name = 'college_workflow'

app.config['MONGO_URI'] = f"{mongo_uri}/{db_name}"
mongo = PyMongo(app)

# Routes
@app.route('/')
def home():
    if 'username' in session:
        role = session.get('role')
        events = mongo.db.events.find() if role in ['junior', 'senior'] else []
        tasks = mongo.db.tasks.find() if role in ['junior', 'senior'] else []
        complaints = mongo.db.complaints.find() if role in ['teaching_staff', 'non_teaching_staff'] else []
        broadcasts = mongo.db.broadcasts.find() if role in ['teaching_staff', 'non_teaching_staff'] else []
        return render_template('index.html', events=events, tasks=tasks, complaints=complaints, broadcasts=broadcasts)
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']

        if not username or not password or not role:
            flash('All fields are required!', 'danger')
            return redirect(url_for('register'))

        # Check if the username already exists
        user = mongo.db.users.find_one({'username': username})
        if user:
            flash('Username already exists!', 'danger')
            return redirect(url_for('register'))

        # Insert new user with hashed password
        hashed_password = generate_password_hash(password)
        mongo.db.users.insert_one({'username': username, 'password': hashed_password, 'role': role})
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('registration.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Validate credentials here
        user = mongo.db.users.find_one({'username': username})
        if user and check_password_hash(user['password'], password):
            session['username'] = username
            session['role'] = user['role']
            return redirect(url_for('dashboard'))
        else:
            return render_template('login.html', error="Invalid username or password!")

    return render_template('login.html')


@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        flash('You need to log in first!', 'danger')
        return redirect(url_for('login'))

    role = session.get('role')
    username = session.get('username')

    # Retrieve data based on role
    if role == 'junior':
        # Retrieve all tasks for juniors
        tasks = mongo.db.tasks.find()
        events = mongo.db.events.find()
        return render_template('junior_dashboard.html', username=username, tasks=tasks, events=events)

    elif role == 'senior':
        events = mongo.db.events.find({'posted_by': username})
        return render_template('senior_dashboard.html', username=username, events=events)

    elif role == 'teaching_staff':
        # Retrieve tasks created by teaching staff
        tasks = mongo.db.tasks.find({'created_by': username})
        complaints = mongo.db.complaints.find()
        broadcasts = mongo.db.broadcasts.find()
        return render_template(
            'teaching_staff_dashboard.html', username=username, tasks=tasks, complaints=complaints, broadcasts=broadcasts
        )

    elif role == 'non_teaching_staff':
        tasks = mongo.db.tasks.find()
        complaints = mongo.db.complaints.find()
        broadcasts = mongo.db.broadcasts.find()
        return render_template(
            'non_teaching_staff_dashboard.html', username=username, tasks=tasks, complaints=complaints, broadcasts=broadcasts
        )

    flash('Invalid role!', 'danger')
    return redirect(url_for('home'))

@app.route('/post_event', methods=['POST'])
def post_event():
    if 'username' not in session:
        flash('You need to log in first!', 'danger')
        return redirect(url_for('login'))

    event_description = request.form['event']
    username = session['username']

    if event_description:
        # Insert event into the MongoDB events collection
        mongo.db.events.insert_one({'event': event_description, 'posted_by': username})
        flash('Event posted successfully!', 'success')
    else:
        flash('Event description is required!', 'danger')
    
    return redirect(url_for('dashboard'))

@app.route('/assign_task', methods=['POST'])
def assign_task():
    if 'username' not in session:
        flash('You need to log in first!', 'danger')
        return redirect(url_for('login'))

    task_description = request.form['task']

    if task_description:
        # Save task without assigning it to a specific user
        mongo.db.tasks.insert_one({
            'task': task_description,
            'created_by': session['username']
        })
        flash('Task assigned successfully!', 'success')
    else:
        flash('Task description is required!', 'danger')

    return redirect(url_for('dashboard'))

@app.route('/raise_complaint', methods=['POST'])
def raise_complaint():
    if request.method == 'POST':
        complaint = request.form['complaint']
        if complaint:
            mongo.db.complaints.insert_one({'complaint': complaint, 'raised_by': session['username']})
            flash('Complaint raised successfully!', 'success')
        else:
            flash('Complaint description is required!', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/broadcast', methods=['POST'])
def broadcast():
    if request.method == 'POST':
        broadcast_message = request.form['broadcast']
        if broadcast_message:
            mongo.db.broadcasts.insert_one({'message': broadcast_message, 'posted_by': session['username']})
            flash('Broadcast posted successfully!', 'success')
        else:
            flash('Broadcast message is required!', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully!', 'success')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
