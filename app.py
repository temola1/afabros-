from flask import Flask, render_template_string, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import json

app = Flask(__name__)
app.config['SECRET_KEY'] = 'afabros_computer_college_secret_key_2024'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cbt_exam.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    full_name = db.Column(db.String(150), nullable=False)
    phone = db.Column(db.String(20))
    role = db.Column(db.String(20), default='student')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def set_password(self, password):
        self.password = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password, password)

class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    question_text = db.Column(db.Text, nullable=False)
    option_a = db.Column(db.String(300), nullable=False)
    option_b = db.Column(db.String(300), nullable=False)
    option_c = db.Column(db.String(300), nullable=False)
    option_d = db.Column(db.String(300), nullable=False)
    correct_answer = db.Column(db.String(1), nullable=False)
    subject = db.Column(db.String(100), nullable=False)
    difficulty = db.Column(db.String(20), default='medium')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class ExamResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    subject = db.Column(db.String(100), nullable=False)
    score = db.Column(db.Integer, nullable=False)
    total_questions = db.Column(db.Integer, nullable=False)
    percentage = db.Column(db.Float, nullable=False)
    time_taken = db.Column(db.Integer)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    user = db.relationship('User', backref=db.backref('exam_results', lazy=True))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ===== ALL TEMPLATES IN ONE FILE =====

BASE_HTML = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{% block title %}Afabros Computer College - CBT System{% endblock %}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        body { font-family: Arial, sans-serif; background: #f8f9fa; }
        .navbar-brand { font-weight: bold; }
        .card { box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px; }
        .btn { border-radius: 5px; }
    </style>
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-primary">
        <div class="container">
            <a class="navbar-brand" href="/">
                <i class="fas fa-laptop-code"></i> Afabros Computer College
            </a>
        </div>
    </nav>

    <div class="container mt-4">
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="alert alert-{{ category }} alert-dismissible fade show">
                        {{ message }}
                        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                    </div>
                {% endfor %}
            {% endif %}
        {% endwith %}

        {% block content %}{% endblock %}
    </div>

    <footer class="bg-dark text-light text-center py-3 mt-5">
        <div class="container">
            <p>&copy; 2024 Afabros Computer College. All rights reserved.</p>
        </div>
    </footer>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
'''

INDEX_HTML = BASE_HTML.replace('{% block content %}{% endblock %}', '''
<div class="text-center py-5 bg-light rounded">
    <h1 class="display-4 text-primary">
        <i class="fas fa-graduation-cap"></i> Welcome to Afabros Computer College
    </h1>
    <p class="lead">Computer Based Test (CBT) Examination System</p>
    
    {% if not current_user.is_authenticated %}
        <div class="mt-4">
            <a href="/register" class="btn btn-primary btn-lg me-2">
                <i class="fas fa-user-plus"></i> Register
            </a>
            <a href="/login" class="btn btn-outline-primary btn-lg">
                <i class="fas fa-sign-in-alt"></i> Login
            </a>
        </div>
    {% else %}
        <div class="mt-4">
            {% if current_user.role == 'admin' %}
                <a href="/admin/dashboard" class="btn btn-primary btn-lg">
                    <i class="fas fa-tachometer-alt"></i> Admin Dashboard
                </a>
            {% else %}
                <a href="/dashboard" class="btn btn-primary btn-lg me-2">
                    <i class="fas fa-tachometer-alt"></i> Dashboard
                </a>
                <a href="/exam" class="btn btn-success btn-lg">
                    <i class="fas fa-play-circle"></i> Take Exam
                </a>
            {% endif %}
        </div>
    {% endif %}
</div>
''')

LOGIN_HTML = BASE_HTML.replace('{% block content %}{% endblock %}', '''
<div class="row justify-content-center">
    <div class="col-md-5">
        <div class="card">
            <div class="card-header bg-primary text-white">
                <h4 class="mb-0"><i class="fas fa-sign-in-alt"></i> Login</h4>
            </div>
            <div class="card-body">
                <form method="POST">
                    <div class="mb-3">
                        <label class="form-label">Username</label>
                        <input type="text" class="form-control" name="username" required>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Password</label>
                        <input type="password" class="form-control" name="password" required>
                    </div>
                    <button type="submit" class="btn btn-primary w-100">Login</button>
                </form>
                <div class="text-center mt-3">
                    <p>Don't have an account? <a href="/register">Register here</a></p>
                </div>
                <div class="alert alert-info mt-3">
                    <strong>Demo Admin:</strong> username: <code>admin</code> | password: <code>admin123</code>
                </div>
            </div>
        </div>
    </div>
</div>
''')

REGISTER_HTML = BASE_HTML.replace('{% block content %}{% endblock %}', '''
<div class="row justify-content-center">
    <div class="col-md-6">
        <div class="card">
            <div class="card-header bg-primary text-white">
                <h4 class="mb-0"><i class="fas fa-user-plus"></i> Student Registration</h4>
            </div>
            <div class="card-body">
                <form method="POST">
                    <div class="mb-3">
                        <label class="form-label">Full Name</label>
                        <input type="text" class="form-control" name="full_name" required>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Username</label>
                        <input type="text" class="form-control" name="username" required>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Email</label>
                        <input type="email" class="form-control" name="email" required>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Phone</label>
                        <input type="tel" class="form-control" name="phone" required>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Password</label>
                        <input type="password" class="form-control" name="password" required>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Confirm Password</label>
                        <input type="password" class="form-control" name="confirm_password" required>
                    </div>
                    <button type="submit" class="btn btn-primary w-100">Register</button>
                </form>
                <div class="text-center mt-3">
                    <p>Already have an account? <a href="/login">Login here</a></p>
                </div>
            </div>
        </div>
    </div>
</div>
''')

DASHBOARD_HTML = BASE_HTML.replace('{% block content %}{% endblock %}', '''
<div class="card">
    <div class="card-header bg-success text-white">
        <h4 class="mb-0"><i class="fas fa-tachometer-alt"></i> Student Dashboard</h4>
    </div>
    <div class="card-body">
        <h5>Welcome, {{ current_user.full_name }}!</h5>
        <p>You are logged in as a student.</p>
        
        <div class="row mt-4">
            <div class="col-md-6">
                <div class="card text-center bg-light">
                    <div class="card-body">
                        <i class="fas fa-play-circle fa-2x text-primary mb-2"></i>
                        <h5>Take Exam</h5>
                        <a href="/exam" class="btn btn-primary">Start Exam</a>
                    </div>
                </div>
            </div>
            <div class="col-md-6">
                <div class="card text-center bg-light">
                    <div class="card-body">
                        <i class="fas fa-chart-bar fa-2x text-success mb-2"></i>
                        <h5>View Results</h5>
                        <a href="/results" class="btn btn-success">View Results</a>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>
''')

# ===== ROUTES =====

@app.route('/')
def index():
    return render_template_string(INDEX_HTML)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        full_name = request.form['full_name']
        phone = request.form['phone']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if password != confirm_password:
            flash('Passwords do not match!', 'danger')
            return redirect('/register')
        
        existing_user = User.query.filter(
            (User.username == username) | (User.email == email)
        ).first()
        
        if existing_user:
            flash('Username or email already exists!', 'danger')
            return redirect('/register')
        
        new_user = User(
            username=username,
            email=email,
            full_name=full_name,
            phone=phone,
            role='student'
        )
        new_user.set_password(password)
        
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration successful! Please login.', 'success')
        return redirect('/login')
    
    return render_template_string(REGISTER_HTML)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            if user.role == 'admin':
                return redirect('/admin/dashboard')
            else:
                return redirect('/dashboard')
        else:
            flash('Invalid username or password.', 'danger')
    
    return render_template_string(LOGIN_HTML)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect('/')

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'admin':
        return redirect('/admin/dashboard')
    return render_template_string(DASHBOARD_HTML)

@app.route('/exam')
@login_required
def exam():
    return render_template_string(BASE_HTML.replace('{% block content %}{% endblock %}', '''
    <div class="card">
        <div class="card-header bg-primary text-white">
            <h4 class="mb-0"><i class="fas fa-play-circle"></i> Available Exams</h4>
        </div>
        <div class="card-body">
            <div class="alert alert-info">
                <i class="fas fa-info-circle"></i>
                Exams will be available soon. Please check back later.
            </div>
        </div>
    </div>
    '''))
    # Admin Dashboard HTML
ADMIN_DASHBOARD_HTML = BASE_HTML.replace('{% block content %}{% endblock %}', '''
<div class="card">
    <div class="card-header bg-dark text-white">
        <h4 class="mb-0"><i class="fas fa-cogs"></i> Admin Dashboard</h4>
    </div>
    <div class="card-body">
        <h5>Welcome, Admin!</h5>
        <p>You are logged in as an administrator.</p>
        
        <div class="row mt-4">
            <div class="col-md-3">
                <div class="card text-center bg-primary text-white">
                    <div class="card-body">
                        <i class="fas fa-users fa-2x mb-2"></i>
                        <h5>Manage Users</h5>
                        <a href="/admin/users" class="btn btn-light btn-sm">View Users</a>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card text-center bg-success text-white">
                    <div class="card-body">
                        <i class="fas fa-question-circle fa-2x mb-2"></i>
                        <h5>Manage Questions</h5>
                        <a href="/admin/questions" class="btn btn-light btn-sm">View Questions</a>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card text-center bg-warning text-dark">
                    <div class="card-body">
                        <i class="fas fa-plus-circle fa-2x mb-2"></i>
                        <h5>Add Question</h5>
                        <a href="/admin/add_question" class="btn btn-dark btn-sm">Add New</a>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card text-center bg-info text-white">
                    <div class="card-body">
                        <i class="fas fa-chart-bar fa-2x mb-2"></i>
                        <h5>Statistics</h5>
                        <a href="/admin/stats" class="btn btn-light btn-sm">View Stats</a>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>
''')

ADMIN_USERS_HTML = BASE_HTML.replace('{% block content %}{% endblock %}', '''
<div class="card">
    <div class="card-header bg-dark text-white">
        <h4 class="mb-0"><i class="fas fa-users"></i> Manage Users</h4>
    </div>
    <div class="card-body">
        <div class="table-responsive">
            <table class="table table-striped">
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Username</th>
                        <th>Full Name</th>
                        <th>Email</th>
                        <th>Role</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {% for user in users %}
                    <tr>
                        <td>{{ user.id }}</td>
                        <td>{{ user.username }}</td>
                        <td>{{ user.full_name }}</td>
                        <td>{{ user.email }}</td>
                        <td>
                            <span class="badge {% if user.role == 'admin' %}bg-danger{% else %}bg-primary{% endif %}">
                                {{ user.role }}
                            </span>
                        </td>
                        <td>
                            {% if user.role != 'admin' %}
                            <a href="/admin/delete_user/{{ user.id }}" class="btn btn-sm btn-danger" 
                               onclick="return confirm('Delete this user?')">
                                Delete
                            </a>
                            {% else %}
                            <span class="text-muted">System Admin</span>
                            {% endif %}
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
    </div>
</div>
''')

ADMIN_QUESTIONS_HTML = BASE_HTML.replace('{% block content %}{% endblock %}', '''
<div class="card">
    <div class="card-header bg-dark text-white">
        <h4 class="mb-0"><i class="fas fa-question-circle"></i> Manage Questions</h4>
        <a href="/admin/add_question" class="btn btn-primary btn-sm float-end">Add New Question</a>
    </div>
    <div class="card-body">
        {% if questions %}
        <div class="table-responsive">
            <table class="table table-striped">
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Question</th>
                        <th>Subject</th>
                        <th>Correct Answer</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {% for question in questions %}
                    <tr>
                        <td>{{ question.id }}</td>
                        <td>{{ question.question_text[:50] }}...</td>
                        <td><span class="badge bg-info">{{ question.subject }}</span></td>
                        <td><span class="badge bg-success">{{ question.correct_answer }}</span></td>
                        <td>
                            <a href="/admin/delete_question/{{ question.id }}" class="btn btn-sm btn-danger"
                               onclick="return confirm('Delete this question?')">
                                Delete
                            </a>
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        {% else %}
        <div class="alert alert-warning text-center">
            <i class="fas fa-exclamation-triangle"></i>
            No questions found. <a href="/admin/add_question">Add your first question</a>
        </div>
        {% endif %}
    </div>
</div>
''')

ADD_QUESTION_HTML = BASE_HTML.replace('{% block content %}{% endblock %}', '''
<div class="card">
    <div class="card-header bg-dark text-white">
        <h4 class="mb-0"><i class="fas fa-plus-circle"></i> Add New Question</h4>
    </div>
    <div class="card-body">
        <form method="POST">
            <div class="mb-3">
                <label class="form-label">Subject</label>
                <input type="text" class="form-control" name="subject" required 
                       placeholder="e.g., Mathematics, English">
            </div>
            <div class="mb-3">
                <label class="form-label">Question Text</label>
                <textarea class="form-control" name="question_text" rows="3" required></textarea>
            </div>
            <div class="row">
                <div class="col-md-6">
                    <div class="mb-3">
                        <label class="form-label">Option A</label>
                        <input type="text" class="form-control" name="option_a" required>
                    </div>
                </div>
                <div class="col-md-6">
                    <div class="mb-3">
                        <label class="form-label">Option B</label>
                        <input type="text" class="form-control" name="option_b" required>
                    </div>
                </div>
            </div>
            <div class="row">
                <div class="col-md-6">
                    <div class="mb-3">
                        <label class="form-label">Option C</label>
                        <input type="text" class="form-control" name="option_c" required>
                    </div>
                </div>
                <div class="col-md-6">
                    <div class="mb-3">
                        <label class="form-label">Option D</label>
                        <input type="text" class="form-control" name="option_d" required>
                    </div>
                </div>
            </div>
            <div class="mb-3">
                <label class="form-label">Correct Answer</label>
                <select class="form-select" name="correct_answer" required>
                    <option value="">Select correct answer</option>
                    <option value="A">A</option>
                    <option value="B">B</option>
                    <option value="C">C</option>
                    <option value="D">D</option>
                </select>
            </div>
            <button type="submit" class="btn btn-primary">Save Question</button>
            <a href="/admin/questions" class="btn btn-secondary">Back to Questions</a>
        </form>
    </div>
</div>
''')

# Admin Routes
@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        flash('Access denied!', 'danger')
        return redirect('/dashboard')
    return render_template_string(ADMIN_DASHBOARD_HTML)

@app.route('/admin/users')
@login_required
def admin_users():
    if current_user.role != 'admin':
        flash('Access denied!', 'danger')
        return redirect('/dashboard')
    
    users = User.query.all()
    return render_template_string(ADMIN_USERS_HTML, users=users)

@app.route('/admin/questions')
@login_required
def admin_questions():
    if current_user.role != 'admin':
        flash('Access denied!', 'danger')
        return redirect('/dashboard')
    
    questions = Question.query.all()
    return render_template_string(ADMIN_QUESTIONS_HTML, questions=questions)

@app.route('/admin/add_question', methods=['GET', 'POST'])
@login_required
def add_question():
    if current_user.role != 'admin':
        flash('Access denied!', 'danger')
        return redirect('/dashboard')
    
    if request.method == 'POST':
        question_text = request.form['question_text']
        option_a = request.form['option_a']
        option_b = request.form['option_b']
        option_c = request.form['option_c']
        option_d = request.form['option_d']
        correct_answer = request.form['correct_answer']
        subject = request.form['subject']
        
        question = Question(
            question_text=question_text,
            option_a=option_a,
            option_b=option_b,
            option_c=option_c,
            option_d=option_d,
            correct_answer=correct_answer,
            subject=subject
        )
        
        db.session.add(question)
        db.session.commit()
        
        flash('Question added successfully!', 'success')
        return redirect('/admin/questions')
    
    return render_template_string(ADD_QUESTION_HTML)

@app.route('/admin/delete_question/<int:question_id>')
@login_required
def delete_question(question_id):
    if current_user.role != 'admin':
        flash('Access denied!', 'danger')
        return redirect('/dashboard')
    
    question = Question.query.get(question_id)
    if question:
        db.session.delete(question)
        db.session.commit()
        flash('Question deleted successfully!', 'success')
    return redirect('/admin/questions')

@app.route('/admin/delete_user/<int:user_id>')
@login_required
def delete_user(user_id):
    if current_user.role != 'admin':
        flash('Access denied!', 'danger')
        return redirect('/dashboard')
    
    user = User.query.get(user_id)
    if user and user.role != 'admin':
        db.session.delete(user)
        db.session.commit()
        flash('User deleted successfully!', 'success')
    elif user and user.role == 'admin':
        flash('Cannot delete admin user!', 'danger')
    
    return redirect('/admin/users')

# Initialize database
with app.app_context():
    db.create_all()
    
    # Create admin user if not exists
    admin_user = User.query.filter_by(username='admin').first()
    if not admin_user:
        admin = User(
            username='admin',
            email='admin@afabros.edu',
            full_name='System Administrator',
            role='admin'
        )
        admin.set_password('admin123')
        db.session.add(admin)
        db.session.commit()
        print("Admin user created: username='admin', password='admin123'")

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)