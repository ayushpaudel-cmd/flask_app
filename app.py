from flask import Flask, flash, render_template, request, session, redirect, url_for
import bcrypt
from flask_wtf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from pymongo import MongoClient
from bson.objectid import ObjectId
from pymongo.errors import DuplicateKeyError
from functools import wraps
from datetime import datetime
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask("MyFlaskApp")
app.secret_key = os.getenv('SECRET_KEY')

# MongoDB setup
client = MongoClient(os.getenv("MONGO_URI"))
db = client['auth_app']
users = db['users']
notes = db['notes']
questions_col = db['questions']
answers_col = db['answers']
users.create_index("username", unique=True)
try:
    # Prevent duplicate identical answers 
    answers_col.create_index([
        ("question_id", 1),
        ("author_id", 1),
        ("content_key", 1),
    ], unique=True, sparse=True)
except Exception:
    pass

# Security
csrf = CSRFProtect(app)
limiter = Limiter(key_func=get_remote_address)
limiter.init_app(app)

# Subjects map
SUBJECTS = {
    'calc1': 'CALCULUS I',
    'cse1310': 'CSE 1310',
    'hist': 'History',
    'pols': 'Political Science',
}

# Auth decorator
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

# ----------------- ROUTES -----------------

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username'].strip().lower()
        password = request.form['password']

        if not password or len(password) < 8:
            flash("Password must be at least 8 characters", "error")
            return redirect(url_for('signup'))

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        try:
            users.insert_one({"username": username, "password": hashed_password.decode()})
        except DuplicateKeyError:
            flash("Username already exists", "error")
            return redirect(url_for('signup'))

        return redirect(url_for('login'))

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per 30 seconds", methods=["POST"])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip().lower()
        password = request.form['password']

        user = users.find_one({"username": username})
        if not user or not bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
            flash("Invalid username or password", "error")
            return redirect(url_for('login'))

        session.clear()
        session['user_id'] = str(user['_id'])
        session['username'] = user['username']
        return redirect(url_for('dashboard'))

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# ---------- Dashboard & Notes ----------

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', subjects=SUBJECTS)

@app.route('/subjects')
@login_required
def subjects():
    return render_template('subjects.html', subjects=SUBJECTS)

@app.route('/subjects/<subject>')
@login_required
def subject_notes(subject):
    subject_name = SUBJECTS.get(subject)
    if not subject_name:
        return "Subject not found", 404

    subject_notes_list = list(notes.find({"subject": subject}).sort("created_at", -1))
    return render_template('subject_notes.html', subject=subject_name, notes=subject_notes_list)

@app.route('/notes/new', methods=['GET', 'POST'])
@login_required
def new_note():
    if request.method == 'POST':
        notes.insert_one({
            "title": request.form["title"],
            "content": request.form["content"],
            "subject": request.form["subject"],
            "author_id": session["user_id"],
            "author": session["username"],
            "created_at": datetime.utcnow()
        })
        flash("Note submitted successfully", "success")
        return redirect(url_for('subject_notes', subject=request.form["subject"]))

    return render_template('new_note.html', subjects=SUBJECTS)

@app.route('/my-notes')
@login_required
def my_notes():
    my_notes_list = list(notes.find({"author_id": session["user_id"]}).sort("created_at", -1))
    return render_template('my_notes.html', notes=my_notes_list, subjects=SUBJECTS)

# ---------- Q&A Section ----------

@app.route('/questions')
def questions():
    q = request.args.get('q', '').strip()
    subject = request.args.get('subject', '').strip()

    mongo_query = {}
    if q:
        mongo_query["$or"] = [
            {"title": {"$regex": q, "$options": "i"}},
            {"content": {"$regex": q, "$options": "i"}}
        ]
    if subject:
        mongo_query["subject"] = subject

    qs = list(questions_col.find(mongo_query).sort("created_at", -1))
    return render_template('questions.html', questions=qs, subjects=SUBJECTS, q=q, selected_subject=subject)

@app.route('/questions/new', methods=['GET', 'POST'])
@login_required
def new_question():
    if request.method == 'POST':
        questions_col.insert_one({
            "title": request.form["title"],
            "content": request.form["content"],
            "subject": request.form.get("subject"),
            "author_id": session["user_id"],
            "author": session["username"],
            "created_at": datetime.utcnow()
        })
        flash("Question posted", "success")
        return redirect(url_for('questions'))

    return render_template('new_question.html', subjects=SUBJECTS)

@app.route('/questions/<question_id>')
def question_detail(question_id):
    try:
        q = questions_col.find_one({"_id": ObjectId(question_id)})
    except Exception:
        q = None

    if not q:
        return "Question not found", 404

    ans = list(answers_col.find({"question_id": str(q["_id"])}).sort("created_at", -1))
    return render_template('question_detail.html', question=q, answers=ans, subjects=SUBJECTS)

@app.route('/questions/<question_id>/answer', methods=['POST'])
@login_required
def submit_answer(question_id):
    try:
        q = questions_col.find_one({"_id": ObjectId(question_id)})
    except Exception:
        q = None
    if not q:
        return "Question not found", 404

    content_raw = request.form["content"].strip()
    # Normalize content to detect duplicates (case-insensitive, collapse whitespace)
    content_key = " ".join(content_raw.split()).lower()

    # Block duplicate identical answers by same user on same question
    existing = answers_col.find_one({
        "question_id": str(q["_id"]),
        "author_id": session["user_id"],
        "$or": [
            {"content_key": content_key},
            {"content": {"$regex": f"^{content_raw}$", "$options": "i"}}
        ]
    })
    if existing:
        flash("You already posted this exact answer.", "error")
        return redirect(url_for('question_detail', question_id=question_id))

    answers_col.insert_one({
        "question_id": str(q["_id"]),
        "content": content_raw,
        "content_key": content_key,
        "author_id": session["user_id"],
        "author": session["username"],
        "created_at": datetime.utcnow()
    })
    flash("Answer submitted", "success")
    return redirect(url_for('question_detail', question_id=question_id))

# ---------- RUN ----------
if __name__ == '__main__':
    app.run()
