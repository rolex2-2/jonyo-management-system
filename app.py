import tempfile
import io
import zipfile
import pandas as pd
import pytz
from flask import Flask, request, flash, redirect, url_for, send_file, session, render_template
from flask_login import LoginManager, UserMixin, login_required, current_user, login_user, logout_user
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from wtforms import StringField, SelectField, FileField, TextAreaField, RadioField, SubmitField, PasswordField, IntegerField
from wtforms.validators import DataRequired, Optional, Regexp, EqualTo, ValidationError, NumberRange, Length
from werkzeug.utils import secure_filename
from werkzeug.security import check_password_hash, generate_password_hash
import sqlite3
from flask import request
from werkzeug.datastructures import CombinedMultiDict
from wtforms.validators import InputRequired
import os
import shutil
import logging
import random
import string
from datetime import datetime
import hashlib
import time
import csv
import uuid

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_FILE_DIR'] = os.path.join(app.instance_path, 'sessions')
app.config['SESSION_PERMANENT'] = True
app.config['SESSION_USE_SIGNER'] = True
app.config['UPLOAD_FOLDER'] = 'static/uploads/notes'
app.config['UPLOAD_FOLDER'] = 'static/uploads/exams'
ALLOWED_EXTENSIONS = {'pdf', 'doc', 'docx', 'txt', 'jpg', 'jpeg', 'png', 'csv'}
app.config['SECRET_KEY'] = 'your-secret-key'  # Required for WTForms CSRF


# Ensure session directory exists
if not os.path.exists(app.config['SESSION_FILE_DIR']):
    os.makedirs(app.config['SESSION_FILE_DIR'])
    os.chmod(app.config['SESSION_FILE_DIR'], 0o755)
logging.info(f"Session directory set to: {app.config['SESSION_FILE_DIR']}, exists: {os.path.exists(app.config['SESSION_FILE_DIR'])}, writable: {os.access(app.config['SESSION_FILE_DIR'], os.W_OK)}")

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'pdf', 'doc', 'docx'}

# Configure Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Configure logging
logging.basicConfig(filename='app.log', level=logging.DEBUG,
                    format='%(asctime)s:%(levelname)s:%(message)s')

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, id, username, role, full_name):
        self.id = id
        self.username = username
        self.role = role
        self.full_name = full_name

@login_manager.user_loader
def load_user(user_id):
    conn = sqlite3.connect('jonyo_school.db')
    c = conn.cursor()
    c.execute("SELECT id, username, role, full_name FROM users WHERE id=?", (user_id,))
    user_data = c.fetchone()
    conn.close()
    if user_data:
        return User(user_data[0], user_data[1], user_data[2], user_data[3])
    return None

# Stub for delete_expired_exams_route
def delete_expired_exams_route():
    try:
        with sqlite3.connect('C:/Users/USER/Desktop/jonyo school/jonyo_school.db') as conn:
            c = conn.cursor()
            now = datetime.now(pytz.timezone('Africa/Nairobi')).strftime('%Y-%m-%d %H:%M:%S')
            c.execute("DELETE FROM exams WHERE end_time < ? AND is_active=1", (now,))
            deleted_count = c.rowcount
            conn.commit()
            return deleted_count
    except sqlite3.Error as e:
        logging.error(f"Error deleting expired exams: {str(e)}")
        return 0

# Define ExamForm
class ExamForm(FlaskForm):
    grade = SelectField('Grade', choices=[('', 'Select Grade')] + [(g, g) for g in ['Grade 7', 'Grade 8', 'Grade 9']], validators=[DataRequired()])
    learning_area = SelectField('Learning Area', choices=[], validators=[DataRequired()])
    exam_name = StringField('Exam Name', validators=[DataRequired()])
    start_time = StringField('Start Time', validators=[DataRequired()])
    end_time = StringField('End Time', validators=[DataRequired()])
    is_online = SelectField('Online Exam', choices=[('0', 'No'), ('1', 'Yes')])
    file = FileField('Upload File')
    question_1 = StringField('Question 1')
    question_2 = StringField('Question 2')
    question_3 = StringField('Question 3')
    question_4 = StringField('Question 4')
    question_5 = StringField('Question 5')


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'pdf', 'doc', 'docx'}

 # Define MessageForm for admin announcements
class MessageForm(FlaskForm):
    message = TextAreaField('Message', validators=[DataRequired(), Length(max=500)])
    submit = SubmitField('Send Message')

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'csv', 'xlsx', 'xls', 'jpg', 'jpeg', 'png'}

def generate_teacher_password():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=8))

def validate_learner_data(file_path, grade):
    learners_data = []
    file_ext = os.path.splitext(file_path)[1].lower()
    
    if file_ext == '.csv':
        with open(file_path, 'r', encoding='utf-8') as f:
            csv_reader = csv.DictReader(f)
            # Map 'admission' to 'admission_no' and 'name' to 'full_name' if present
            fieldnames = csv_reader.fieldnames
            if 'admission' in fieldnames and 'admission_no' not in fieldnames:
                fieldnames[fieldnames.index('admission')] = 'admission_no'
            if 'name' in fieldnames and 'full_name' not in fieldnames:
                fieldnames[fieldnames.index('name')] = 'full_name'
            required_columns = ['admission_no', 'full_name']
            if not all(col in fieldnames for col in required_columns):
                raise ValueError("File missing required columns: admission_no, full_name")
            for row in csv_reader:
                learners_data.append({
                    'admission_no': row['admission_no'].strip(),
                    'full_name': row['full_name'].strip(),
                    'grade': grade,  # Use selected grade
                    'parent_phone': row.get('parent_phone', '').strip() or None,
                    'photo_path': row.get('photo_path', 'N/A').strip() or 'N/A'
                })
    elif file_ext in ('.xlsx', '.xls'):
        df = pd.read_excel(file_path)
        # Map 'admission' to 'admission_no' and 'name' to 'full_name'
        df = df.rename(columns={'admission': 'admission_no', 'name': 'full_name'})
        required_columns = ['admission_no', 'full_name']
        if not all(col in df.columns for col in required_columns):
            raise ValueError("File missing required columns: admission_no, full_name")
        for _, row in df.iterrows():
            learners_data.append({
                'admission_no': str(row['admission_no']).strip(),
                'full_name': str(row['full_name']).strip(),
                'grade': grade,  # Use selected grade
                'parent_phone': str(row['parent_phone']).strip() if 'parent_phone' in df.columns and pd.notna(row['parent_phone']) else None,
                'photo_path': str(row['photo_path']).strip() if 'photo_path' in df.columns and pd.notna(row['photo_path']) else 'N/A'
            })
    else:
        raise ValueError("Unsupported file type. Allowed: .csv, .xlsx, .xls")
    
    return learners_data
# Form definitions
class MessageForm(FlaskForm):
    message = TextAreaField('Message', validators=[DataRequired(), Length(max=500)])
    submit = SubmitField('Send Message')

class ManageMarksForm(FlaskForm):
    learner_id = StringField('Learner Admission No', validators=[DataRequired()])
    learning_area = SelectField('Learning Area', coerce=int, validators=[DataRequired()])
    exam_type = SelectField('Exam Type', choices=[('Mid Term', 'Mid Term'), ('End Term', 'End Term'), ('CAT', 'CAT')], validators=[DataRequired()])
    marks = IntegerField('Marks', validators=[DataRequired(), NumberRange(min=0, max=100)])
    term = SelectField('Term', choices=[('Term 1', 'Term 1')], validators=[DataRequired()])  # Limited to Term 1
    year = IntegerField('Year', validators=[DataRequired(), NumberRange(min=2000, max=datetime.now().year + 1)])
    submit = SubmitField('Submit Marks')

class PublicRegisterForm(FlaskForm):
    role = SelectField('Role', choices=[('admin', 'Admin'), ('parent', 'Parent'), ('teacher', 'Teacher'), ('bursar', 'Bursar'), ('learner', 'Learner')], validators=[DataRequired()])
    username = StringField('Username', validators=[DataRequired()])
    full_name = StringField('Full Name', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password', message='Passwords must match')])
    phone = StringField('Phone Number', validators=[Optional()])
    learner_admission = StringField('Learner Admission Number', validators=[Optional()])
    submit = SubmitField('Register')

    def validate_username(self, username):
        if not username.data.isalnum():
            raise ValidationError('Username must be alphanumeric.')
        conn = sqlite3.connect('jonyo_school.db')
        c = conn.cursor()
        c.execute("SELECT id FROM users WHERE username=?", (username.data,))
        if c.fetchone():
            conn.close()
            raise ValidationError('Username already exists.')
        conn.close()

    def validate_full_name(self, full_name):
        if len(full_name.data.split()) < 2:
            raise ValidationError('Full name must include at least first and last name.')

    def validate_phone(self, phone):
        if phone.data and not (phone.data.isdigit() and len(phone.data) == 10 and phone.data.startswith('0')):
            raise ValidationError('Phone number must be 10 digits starting with 0.')

    def validate_learner_admission(self, learner_admission):
        if self.role.data == 'parent' and not learner_admission.data:
            raise ValidationError('Learner admission number is required for parents.')
        if learner_admission.data:
            conn = sqlite3.connect('jonyo_school.db')
            c = conn.cursor()
            c.execute("SELECT id FROM learners WHERE admission_no=?", (learner_admission.data,))
            if not c.fetchone():
                conn.close()
                raise ValidationError('Invalid learner admission number.')
            conn.close()

class AdminNoteForm(FlaskForm):
    note_text = TextAreaField('Note Content', validators=[DataRequired()])
    submit = SubmitField('Save Note')

class ExamForm(FlaskForm):
    grade = SelectField('Grade', choices=[('Grade 7', 'Grade 7'), ('Grade 8', 'Grade 8'), ('Grade 9', 'Grade 9')], validators=[DataRequired()])
    learning_area = SelectField('Learning Area', validators=[DataRequired()])
    file = FileField('Exam File', validators=[Optional()])
    start_time = StringField('Start Time (YYYY-MM-DD HH:MM)', validators=[DataRequired()])
    end_time = StringField('End Time (YYYY-MM-DD HH:MM)', validators=[DataRequired()])
    is_online = SelectField('Online Exam', choices=[('0', 'No'), ('1', 'Yes')], validators=[DataRequired()])
    question_1 = TextAreaField('Question 1', validators=[Optional()])
    question_2 = TextAreaField('Question 2', validators=[Optional()])
    question_3 = TextAreaField('Question 3', validators=[Optional()])
    question_4 = TextAreaField('Question 4', validators=[Optional()])
    question_5 = TextAreaField('Question 5', validators=[Optional()])
    submit = SubmitField('Create Exam')

class NoteForm(FlaskForm):
    grade = SelectField('Grade', choices=[('Grade 7', 'Grade 7'), ('Grade 8', 'Grade 8'), ('Grade 9', 'Grade 9')], validators=[DataRequired()])
    learning_area = SelectField('Learning Area', validators=[DataRequired()])
    file = FileField('Note File', validators=[DataRequired()])
    submit = SubmitField('Upload Note')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

# Utility functions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def generate_teacher_password():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=12))

def validate_learner_data(file_path, grade):
    learners = []
    try:
        with open(file_path, 'r') as f:
            reader = pd.read_csv(f)
            required_fields = {'full_name', 'admission_no'}
            for _, row in reader.iterrows():
                if not all(field in row for field in required_fields):
                    continue
                learner = {
                    'full_name': str(row['full_name']).strip(),
                    'admission_no': str(row['admission_no']).strip(),
                    'grade': grade,
                    'parent_phone': str(row.get('parent_phone', '')).strip(),
                    'photo_path': str(row.get('photo_path', '')).strip()
                }
                learners.append(learner)
    except Exception as e:
        logging.error(f"Error validating learner data: {str(e)}")
    return learners

def delete_expired_exams():
    nairobi_tz = pytz.timezone('Africa/Nairobi')
    now = datetime.now(nairobi_tz)
    try:
        with sqlite3.connect('jonyo_school.db') as conn:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            c.execute("SELECT id, exam_name, file_path FROM exams WHERE end_time < ? AND is_active=1",
                      (now.strftime('%Y-%m-%d %H:%M:%S'),))
            expired_exams = c.fetchall()
            for exam in expired_exams:
                if exam['file_path'] and os.path.exists(exam['file_path']):
                    try:
                        os.remove(exam['file_path'])
                        logging.info(f"Deleted file: {exam['file_path']} for exam_id={exam['id']}")
                    except OSError as e:
                        logging.error(f"Error deleting file {exam['file_path']}: {str(e)}")
                c.execute("DELETE FROM exam_questions WHERE exam_id=?", (exam['id'],))
                c.execute("DELETE FROM exam_answers WHERE exam_id=?", (exam['id'],))
                c.execute("DELETE FROM exams WHERE id=?", (exam['id'],))
                logging.info(f"Expired exam deleted: id={exam['id']}, exam_name={exam['exam_name']}, by system")
            conn.commit()
            return len(expired_exams)
    except sqlite3.Error as e:
        logging.error(f"Error deleting expired exams: {str(e)}")
        return 0

@app.context_processor
def inject_tokens():
    delete_token = hashlib.md5(f"{current_user.id if current_user.is_authenticated else 'guest'}{app.config['SECRET_KEY']}{int(time.time())//3600}".encode()).hexdigest()
    return dict(delete_token=delete_token, csrf_token=lambda: session.get('csrf_token', ''))

def init_db():
    conn = sqlite3.connect('jonyo_school.db')
    c = conn.cursor()

    # Check if old messages table exists with message_text
    c.execute("PRAGMA table_info(messages)")
    columns = [info[1] for info in c.fetchall()]
    if 'message_text' in columns or 'sent_at' in columns:
        c.execute("ALTER TABLE messages RENAME TO messages_old")
        logging.info("Renamed old messages table to messages_old for migration.")
        c.execute('''CREATE TABLE messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id INTEGER NOT NULL,
            receiver_id INTEGER,
            message TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            FOREIGN KEY(sender_id) REFERENCES users(id),
            FOREIGN KEY(receiver_id) REFERENCES users(id)
        )''')
        logging.info("Created new messages table with updated schema.")
        c.execute('''INSERT INTO messages (id, sender_id, receiver_id, message, timestamp)
                     SELECT id, sender_id, NULL, message_text, sent_at
                     FROM messages_old''')
        logging.info("Migrated data from messages_old to new messages table.")
        c.execute("DROP TABLE messages_old")
        logging.info("Dropped old messages_old table.")

    # Create tables
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        role TEXT,
        full_name TEXT,
        phone TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS learners (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        full_name TEXT,
        admission_no TEXT UNIQUE,
        grade TEXT,
        parent_phone TEXT,
        photo_path TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS graduated_learners (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        full_name TEXT,
        admission_no TEXT UNIQUE,
        parent_phone TEXT,
        photo_path TEXT,
        graduation_year INTEGER
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS parent_learner (
        parent_id INTEGER,
        learner_admission TEXT,
        PRIMARY KEY (parent_id, learner_admission),
        FOREIGN KEY(parent_id) REFERENCES users(id),
        FOREIGN KEY(learner_admission) REFERENCES learners(admission_no)
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS learning_areas (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        grade TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS marks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        learner_admission TEXT,
        learning_area_id INTEGER,
        marks INTEGER,
        exam_type TEXT,
        term TEXT,
        year INTEGER,
        points REAL,
        grade TEXT,
        teacher_id INTEGER,
        FOREIGN KEY(learner_admission) REFERENCES learners(admission_no),
        FOREIGN KEY(learning_area_id) REFERENCES learning_areas(id),
        FOREIGN KEY(teacher_id) REFERENCES users(id)
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS fees (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        learner_admission TEXT,
        grade TEXT,
        total_fee INTEGER,
        amount_paid INTEGER,
        balance INTEGER,
        term TEXT,
        year INTEGER,
        FOREIGN KEY(learner_admission) REFERENCES learners(admission_no)
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS teacher_notes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        uploaded_by INTEGER,
        grade TEXT,
        learning_area_id INTEGER,
        file_path TEXT,
        upload_date TEXT,
        downloads TEXT,
        FOREIGN KEY(uploaded_by) REFERENCES users(id),
        FOREIGN KEY(learning_area_id) REFERENCES learning_areas(id)
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS exams (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        uploaded_by INTEGER,
        grade TEXT,
        learning_area_id INTEGER,
        file_path TEXT,
        start_time TEXT,
        end_time TEXT,
        is_online INTEGER,
        exam_name TEXT,
        is_active INTEGER DEFAULT 1,
        FOREIGN KEY(uploaded_by) REFERENCES users(id),
        FOREIGN KEY(learning_area_id) REFERENCES learning_areas(id)
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS exam_questions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        exam_id INTEGER,
        question_text TEXT,
        FOREIGN KEY(exam_id) REFERENCES exams(id)
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS exam_answers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        exam_id INTEGER,
        learner_admission TEXT,
        question_id INTEGER,
        answer_text TEXT,
        submitted_at TEXT,
        FOREIGN KEY(exam_id) REFERENCES exams(id),
        FOREIGN KEY(learner_admission) REFERENCES learners(admission_no),
        FOREIGN KEY(question_id) REFERENCES exam_questions(id)
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS timetable (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        grade TEXT,
        day TEXT,
        time_slot TEXT,
        teacher_id INTEGER,
        learning_area_id INTEGER,
        FOREIGN KEY(teacher_id) REFERENCES users(id),
        FOREIGN KEY(learning_area_id) REFERENCES learning_areas(id)
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS total_marks_performance_levels (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 min_total_marks INTEGER NOT NULL,
                 max_total_marks INTEGER NOT NULL,
                 grade TEXT NOT NULL,
                 points REAL NOT NULL,
                 comment TEXT NOT NULL,
                 UNIQUE(min_total_marks, max_total_marks))''')
    c.execute('''CREATE TABLE IF NOT EXISTS performance_levels (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 min_mark INTEGER NOT NULL,
                 max_mark INTEGER NOT NULL,
                 level TEXT NOT NULL,
                 points REAL NOT NULL,
                 comment TEXT NOT NULL,
                 UNIQUE(min_mark, max_mark))''')
    c.execute('''CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender_id INTEGER NOT NULL,
        receiver_id INTEGER,
        message TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        FOREIGN KEY(sender_id) REFERENCES users(id),
        FOREIGN KEY(receiver_id) REFERENCES users(id)
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS term_info (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        term TEXT,
        start_date TEXT,
        end_date TEXT,
        principal_name TEXT,
        is_active INTEGER DEFAULT 0
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS school_info (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        about TEXT,
        contact TEXT,
        announcement TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS class_teachers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        teacher_id INTEGER,
        grade TEXT,
        FOREIGN KEY(teacher_id) REFERENCES users(id)
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS teacher_assignments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        teacher_id INTEGER,
        grade TEXT,
        learning_area_id INTEGER,
        FOREIGN KEY(teacher_id) REFERENCES users(id),
        FOREIGN KEY(learning_area_id) REFERENCES learning_areas(id)
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS admin_notes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        admin_id INTEGER,
        note_text TEXT,
        created_at TEXT,
        FOREIGN KEY(admin_id) REFERENCES users(id)
    )''')

    # Migrate marks table
    c.execute("PRAGMA table_info(marks)")
    columns = [info[1] for info in c.fetchall()]
    if 'points' not in columns:
        c.execute("ALTER TABLE marks ADD COLUMN points REAL")
        logging.info("Added points column to marks table.")
    if 'grade' not in columns:
        c.execute("ALTER TABLE marks ADD COLUMN grade TEXT")
        logging.info("Added grade column to marks table.")
    if 'teacher_id' not in columns:
        c.execute("ALTER TABLE marks ADD COLUMN teacher_id INTEGER")
        logging.info("Added teacher_id column to marks table.")

    c.execute("PRAGMA table_info(exams)")
    columns = [info[1] for info in c.fetchall()]
    if 'exam_name' not in columns:
        c.execute("ALTER TABLE exams ADD COLUMN exam_name TEXT")
        logging.info("Added exam_name column to exams table.")
    if 'is_active' not in columns:
        c.execute("ALTER TABLE exams ADD COLUMN is_active INTEGER DEFAULT 1")
        logging.info("Added is_active column to exams table.")

    c.execute("PRAGMA table_info(term_info)")
    columns = [info[1] for info in c.fetchall()]
    if 'is_active' not in columns:
        c.execute("ALTER TABLE term_info ADD COLUMN is_active INTEGER DEFAULT 0")
        logging.info("Added is_active column to term_info table.")

    c.execute("SELECT COUNT(*) FROM marks WHERE points IS NULL")
    if c.fetchone()[0] > 0:
        c.execute("SELECT min_mark, max_mark, points FROM performance_levels")
        performance_levels = c.fetchall()
        for min_mark, max_mark, points in performance_levels:
            c.execute('''UPDATE marks
                         SET points = ?
                         WHERE marks BETWEEN ? AND ? AND points IS NULL''',
                      (points, min_mark, max_mark))
        logging.info("Populated points column in marks table.")

    c.execute("SELECT COUNT(*) FROM marks WHERE grade IS NULL")
    if c.fetchone()[0] > 0:
        c.execute('''UPDATE marks
                     SET grade = (SELECT l.grade FROM learners l WHERE l.admission_no = marks.learner_admission)
                     WHERE grade IS NULL''')
        logging.info("Populated grade column in marks table.")

    # Initialize default data
    c.execute("SELECT COUNT(*) FROM users WHERE role='admin'")
    if c.fetchone()[0] == 0:
        c.execute("INSERT INTO users (username, password, role, full_name) VALUES (?, ?, ?, ?)",
                  ('admin', generate_password_hash('admin123'), 'admin', 'Admin User'))

    c.execute("SELECT COUNT(*) FROM school_info")
    if c.fetchone()[0] == 0:
        c.execute("INSERT INTO school_info (about, contact, announcement) VALUES (?, ?, ?)",
                  ('Welcome to Jonyo Junior Secondary School.', 'Phone: 0114745401', 'No announcements.'))

    c.execute("SELECT COUNT(*) FROM performance_levels")
    if c.fetchone()[0] == 0:
        levels = [
            (90, 99, 'EE1', 4.0, 'Excellent performance'),
            (75, 89, 'EE2', 3.5, 'Very good performance'),
            (58, 74, 'ME1', 3.0, 'Good performance'),
            (41, 57, 'ME2', 2.5, 'Satisfactory performance'),
            (31, 40, 'AE1', 2.0, 'Needs improvement'),
            (21, 30, 'AE2', 1.5, 'Below average'),
            (11, 20, 'BE1', 1.0, 'Far below expectations'),
            (0, 10, 'BE2', 0.5, 'Poor performance')
        ]
        c.executemany("INSERT INTO performance_levels (min_mark, max_mark, level, points, comment) VALUES (?, ?, ?, ?, ?)", levels)

    c.execute("SELECT COUNT(*) FROM total_marks_performance_levels")
    if c.fetchone()[0] == 0:
        total_levels = [
            (720, 900, 'A', 12.0, 'Outstanding'),
            (600, 719, 'B', 10.0, 'Very Good'),
            (450, 599, 'C', 8.0, 'Good'),
            (300, 449, 'D', 6.0, 'Satisfactory'),
            (0, 299, 'E', 4.0, 'Needs Improvement')
        ]
        c.executemany("INSERT INTO total_marks_performance_levels (min_total_marks, max_total_marks, grade, points, comment) VALUES (?, ?, ?, ?, ?)", total_levels)

    c.execute("SELECT COUNT(*) FROM term_info")
    if c.fetchone()[0] == 0:
        c.execute("INSERT INTO term_info (term, start_date, end_date, principal_name, is_active) VALUES (?, ?, ?, ?, ?)",
                  ('Term 1', '2025-01-01', '2025-04-01', 'Dr. Principal', 1))

    c.execute("SELECT COUNT(*) FROM learning_areas")
    if c.fetchone()[0] == 0:
        areas = ['Mathematics', 'English', 'Kiswahili', 'Integrated Science', 'Pre-technical',
                 'Agriculture and Nutrition', 'Social Studies', 'Creative Arts', 'CRE']
        for grade in ['Grade 7', 'Grade 8', 'Grade 9']:
            for area in areas:
                c.execute("INSERT INTO learning_areas (name, grade) VALUES (?, ?)", (area, grade))

    c.execute("SELECT COUNT(*) FROM learners WHERE admission_no IN ('ADM001', 'ADM002')")
    if c.fetchone()[0] == 0:
        c.execute("INSERT INTO learners (full_name, admission_no, grade) VALUES (?, ?, ?)",
                  ('John Doe', 'ADM001', 'Grade 7'))
        c.execute("INSERT INTO learners (full_name, admission_no, grade) VALUES (?, ?, ?)",
                  ('Jane Smith', 'ADM002', 'Grade 7'))

    c.execute("SELECT id FROM learning_areas WHERE grade='Grade 7' AND name='Mathematics'")
    math_id = c.fetchone()
    if math_id:
        math_id = math_id[0]
    else:
        c.execute("INSERT INTO learning_areas (name, grade) VALUES (?, ?)", ('Mathematics', 'Grade 7'))
        math_id = c.lastrowid

    c.execute("SELECT id FROM learning_areas WHERE grade='Grade 7' AND name='English'")
    eng_id = c.fetchone()
    if eng_id:
        eng_id = eng_id[0]
    else:
        c.execute("INSERT INTO learning_areas (name, grade) VALUES (?, ?)", ('English', 'Grade 7'))
        eng_id = c.lastrowid

    c.execute("INSERT INTO marks (learner_admission, learning_area_id, marks, exam_type, term, year, points, grade, teacher_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
              ('ADM001', math_id, 85, 'End Term', 'Term 1', 2025, 3.5, 'Grade 7', 1))
    c.execute("INSERT INTO marks (learner_admission, learning_area_id, marks, exam_type, term, year, points, grade, teacher_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
              ('ADM001', eng_id, 90, 'End Term', 'Term 1', 2025, 4.0, 'Grade 7', 1))
    c.execute("INSERT INTO marks (learner_admission, learning_area_id, marks, exam_type, term, year, marks, grade, teacher_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
              ('ADM002', math_id, 78, 'End Term', 'Term 1', 2025, 3.5, 'Grade 7', 1))
    c.execute("INSERT INTO marks (learner_admission, learning_area_id, marks, exam_type, term, year, points, grade, teacher_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
              ('ADM002', eng_id, 82, 'End Term', 'Term 1', 2025, 3.5, 'Grade 7', 1))

    c.execute("SELECT COUNT(*) FROM fees WHERE learner_admission IN ('ADM001', 'ADM002')")
    if c.fetchone()[0] == 0:
        c.execute("INSERT INTO fees (learner_admission, grade, total_fee, amount_paid, balance, term, year) VALUES (?, ?, ?, ?, ?, ?, ?)",
                  ('ADM001', 'Grade 7', 10000, 6000, 4000, 'Term 1', 2025))
        c.execute("INSERT INTO fees (learner_admission, grade, total_fee, amount_paid, balance, term, year) VALUES (?, ?, ?, ?, ?, ?, ?)",
                  ('ADM002', 'Grade 7', 10000, 8000, 2000, 'Term 1', 2025))

    c.execute("SELECT COUNT(*) FROM admin_notes")
    if c.fetchone()[0] == 0:
        c.execute("SELECT id FROM users WHERE role='admin'")
        admin_id = c.fetchone()
        if admin_id:
            c.execute("INSERT INTO admin_notes (admin_id, note_text, created_at) VALUES (?, ?, ?)",
                      (admin_id[0], 'Sample admin note', '2025-05-18 12:00:00'))

    conn.commit()
    conn.close()
# Run init_db on startup
init_db()

# Routes
@app.route('/')
def index():
    conn = sqlite3.connect('jonyo_school.db')
    c = conn.cursor()
    
    about = 'Welcome to Jonyo Junior Secondary School.'
    contact = 'Phone: 0114745401'
    announcement = 'No announcements.'
    try:
        c.execute("SELECT COUNT(*) FROM school_info")
        if c.fetchone()[0] > 0:
            c.execute("SELECT about, contact, announcement FROM school_info ORDER BY id DESC LIMIT 1")
            result = c.fetchone()
            if result:
                about, contact, announcement = result
    except sqlite3.Error as e:
        flash(f'Database error fetching school info: {str(e)}', 'danger')
    
    term_info = None
    try:
        c.execute("SELECT term, start_date, end_date, principal_name FROM term_info WHERE is_active=1")
        term_info = c.fetchone()
        if not term_info:
            c.execute("SELECT term, start_date, end_date, principal_name FROM term_info ORDER BY id DESC LIMIT 1")
            term_info = c.fetchone()
    except sqlite3.Error as e:
        flash(f'Database error fetching term info: {str(e)}', 'danger')
    
    user_name = 'Guest'
    user_role = 'none'
    if current_user.is_authenticated:
        user_name = current_user.full_name
        user_role = current_user.role
    
    logging.info(f"Index page accessed by user_id={current_user.id if current_user.is_authenticated else 'guest'}, role={user_role}, name={user_name}")
    
    conn.close()
    
    if not term_info:
        flash('No active term information available.', 'warning')
    
    return render_template('index.html',
                          about_content=about,
                          contact_content=contact,
                          announcement_content=announcement,
                          term_info=term_info,
                          user_name=user_name,
                          user_role=user_role,
                          current_year=datetime.now().year)
    
# /register route (admin-only, all roles, 3-admin limit)
@app.route('/register', methods=['GET', 'POST'])
@login_required
def register():
    if current_user.role != 'admin':
        flash('Unauthorized access.', 'danger')
        logging.warning(f"Unauthorized register attempt by user_id={current_user.id}")
        return redirect(url_for('index'))
    form = PublicRegisterForm()
    if form.validate_on_submit():
        try:
            conn = sqlite3.connect('jonyo_school.db')
            c = conn.cursor()
            # Check admin limit
            if form.role.data == 'admin':
                c.execute("SELECT COUNT(*) FROM users WHERE role='admin'")
                if c.fetchone()[0] >= 3:
                    flash('Maximum number of admins (3) reached.', 'danger')
                    logging.warning(f"Registration failed: Admin limit reached, username={form.username.data}")
                    conn.close()
                    return redirect(url_for('register'))
            # Insert user
            c.execute('''INSERT INTO users (username, password, role, full_name, phone)
                         VALUES (?, ?, ?, ?, ?)''',
                      (form.username.data, generate_password_hash(form.password.data), form.role.data, form.full_name.data, form.phone.data or None))
            user_id = c.lastrowid
            # Link parent to learner
            if form.role.data == 'parent':
                c.execute("INSERT INTO parent_learner (parent_id, learner_admission) VALUES (?, ?)",
                          (user_id, form.learner_admission.data))
            conn.commit()
            flash('Registration successful.', 'success')
            logging.info(f"User registered: username={form.username.data}, role={form.role.data}, by admin={current_user.id}")
            conn.close()
            return redirect(url_for('register'))
        except Exception as e:
            conn.rollback()
            flash(f'Registration error: {str(e)}', 'danger')
            logging.error(f"Error during registration: {str(e)}, username={form.username.data}")
            conn.close()
            return redirect(url_for('register'))
    return render_template('register.html', form=form)

@app.route('/public_register', methods=['GET', 'POST'])
def public_register():
    try:
        conn = sqlite3.connect('jonyo_school.db')
        c = conn.cursor()
        if request.method == 'POST':
            role = request.form.get('role')
            username = request.form.get('username', '').strip()
            full_name = request.form.get('full_name', '').strip()
            password = request.form.get('password', '').strip()
            confirm_password = request.form.get('confirm_password', '').strip()
            phone = request.form.get('phone', '').strip()
            learner_admission = request.form.get('learner_admission', '').strip()
            valid_roles = ['admin', 'parent']
            if not (role in valid_roles and username and full_name and password and confirm_password):
                flash('All required fields must be filled.', 'danger')
                logging.warning(f"Public registration failed: Missing fields, role={role}, username={username}")
                conn.close()
                return redirect(url_for('public_register'))
            if password != confirm_password:
                flash('Passwords do not match.', 'danger')
                logging.warning(f"Public registration failed: Passwords do not match, username={username}")
                conn.close()
                return redirect(url_for('public_register'))
            # Validate username: 3-50 chars, no control chars or SQL-critical chars
            if not (3 <= len(username) <= 50 and all(ord(c) >= 32 and c not in "';\"" for c in username)):
                flash('Username must be 3-50 characters and cannot contain quotes, semicolons, or control characters.', 'danger')
                logging.warning(f"Public registration failed: Invalid username format, username={username}")
                conn.close()
                return redirect(url_for('public_register'))
            if len(full_name.split()) < 2:
                flash('Full name must include at least first and last name.', 'danger')
                logging.warning(f"Public registration failed: Invalid full name, full_name={full_name}")
                conn.close()
                return redirect(url_for('public_register'))
            if role == 'parent' and not (phone and learner_admission):
                flash('Phone number and learner admission number are required for parents.', 'danger')
                logging.warning(f"Public registration failed: Missing parent fields, username={username}")
                conn.close()
                return redirect(url_for('public_register'))
            if phone and not (phone.isdigit() and len(phone) == 10 and phone.startswith('0')):
                flash('Phone number must be 10 digits starting with 0.', 'danger')
                logging.warning(f"Public registration failed: Invalid phone, phone={phone}, username={username}")
                conn.close()
                return redirect(url_for('public_register'))
            try:
                if role == 'admin':
                    c.execute("SELECT COUNT(*) FROM users WHERE role='admin'")
                    admin_count = c.fetchone()[0]
                    if admin_count >= 3:
                        flash('Maximum number of admins (3) reached.', 'danger')
                        logging.warning(f"Public registration failed: Admin limit reached, username={username}")
                        conn.close()
                        return redirect(url_for('public_register'))
                if role == 'parent':
                    c.execute("SELECT COUNT(*) FROM users WHERE role='parent'")
                    parent_count = c.fetchone()[0]
                    if parent_count >= 20000000:
                        flash('Maximum number of parents (20,000,000) reached.', 'danger')
                        logging.warning(f"Public registration failed: Parent limit reached, username={username}")
                        conn.close()
                        return redirect(url_for('public_register'))
                    c.execute("SELECT admission_no FROM learners WHERE admission_no=?", (learner_admission,))
                    if not c.fetchone():
                        flash('Invalid learner admission number.', 'danger')
                        logging.warning(f"Public registration failed: Invalid learner_admission={learner_admission}, username={username}")
                        conn.close()
                        return redirect(url_for('public_register'))
                c.execute("SELECT id FROM users WHERE username=?", (username,))
                if c.fetchone():
                    flash('Username already exists.', 'danger')
                    logging.warning(f"Public registration failed: Username exists, username={username}")
                    conn.close()
                    return redirect(url_for('public_register'))
                hashed_password = generate_password_hash(password)
                c.execute("INSERT INTO users (username, password, role, full_name, phone) VALUES (?, ?, ?, ?, ?)",
                          (username, hashed_password, role, full_name, phone or None))
                user_id = c.lastrowid
                if role == 'parent':
                    c.execute("INSERT INTO parent_learner (parent_id, learner_admission) VALUES (?, ?)",
                              (user_id, learner_admission))
                conn.commit()
                flash('Registration successful. Please login.', 'success')
                logging.info(f"Public registration successful: username={username}, role={role}")
                conn.close()
                return redirect(url_for('login'))
            except sqlite3.Error as e:
                conn.rollback()
                flash(f'Database error: {str(e)}', 'danger')
                logging.error(f"Database error during public registration: {str(e)}, username={username}")
                conn.close()
                return redirect(url_for('public_register'))
        conn.close()
        return render_template('public_register.html')
    except sqlite3.Error as e:
        flash(f'Database connection error: {str(e)}', 'danger')
        logging.error(f"Database connection error in public_register: {str(e)}")
        return redirect(url_for('index'))
    
    
@app.route('/login', methods=['GET', 'POST'])
def login():
    logging.debug(f"Route accessed: {request.url}, Method: {request.method}")
    logging.debug(f"Session data: {dict(session)}")
    logging.debug(f"Session CSRF token: {session.get('csrf_token', 'Not found')}")
    
    if request.method == 'POST':
        # Log the received CSRF token
        csrf_token = request.form.get('csrf_token', 'Not found')
        logging.debug(f"Received CSRF token: {csrf_token}")
        
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        role = request.form.get('role', '').strip()
        
        # Validate inputs
        valid_roles = ['learner', 'admin', 'teacher', 'parent', 'bursar']
        if not username or not password or role not in valid_roles:
            flash('Invalid username, password, or role.', 'danger')
            logging.warning(f"Invalid login attempt: username={username}, role={role}")
            return render_template('login.html')
        
        try:
            with sqlite3.connect('jonyo_school.db') as conn:
                conn.row_factory = sqlite3.Row
                c = conn.cursor()
                
                if role == 'learner':
                    # Authenticate learner with full_name and admission_no
                    c.execute("SELECT admission_no, full_name, grade FROM learners WHERE full_name=? AND admission_no=?", (username, password))
                    user = c.fetchone()
                    if user:
                        if not user['full_name']:
                            flash('Learner name is missing in database. Contact admin.', 'danger')
                            logging.error(f"Missing full_name for admission_no={user['admission_no']}")
                            return render_template('login.html')
                        user_obj = User(user['admission_no'], username, 'learner', user['full_name'])
                        login_user(user_obj, remember=True)
                        session.permanent = True
                        session['user_id'] = user['admission_no']
                        session['role'] = 'learner'
                        session['full_name'] = user['full_name']
                        session['grade'] = user['grade']
                        logging.info(f"Learner logged in: {username}, Grade: {user['grade']}")
                        return redirect(url_for('learner_dashboard'))
                    else:
                        flash('Invalid learner credentials. Ensure full name and admission number are correct.', 'danger')
                        logging.warning(f"Failed learner login: username={username}")
                else:
                    # Authenticate other roles with username and hashed password
                    c.execute("SELECT id, username, password, role, full_name FROM users WHERE username=? AND role=?", (username, role))
                    user = c.fetchone()
                    if user and check_password_hash(user['password'], password):
                        if not user['full_name']:
                            flash('User name is missing in database. Contact admin.', 'danger')
                            logging.error(f"Missing full_name for user_id={user['id']}")
                            return render_template('login.html')
                        user_obj = User(user['id'], user['username'], user['role'], user['full_name'])
                        login_user(user_obj, remember=True)
                        session.permanent = True
                        session['user_id'] = user['id']
                        session['role'] = user['role']
                        session['full_name'] = user['full_name']
                        logging.info(f"User logged in: {username}, Role: {user['role']}")
                        dashboard_map = {
                            'admin': 'admin_dashboard',
                            'teacher': 'teacher_dashboard',
                            'parent': 'parent_dashboard',
                            'bursar': 'bursar_dashboard'
                        }
                        return redirect(url_for(dashboard_map[user['role']]))
                    else:
                        flash('Invalid username or password for selected role.', 'danger')
                        logging.warning(f"Failed login: username={username}, role={role}")
        
        except sqlite3.Error as e:
            flash('Database error. Please try again later.', 'danger')
            logging.error(f"Database error during login: {str(e)}")
            return render_template('login.html')
        
        return render_template('login.html')
    
    return render_template('login.html')
@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()
    flash('Logged out successfully.', 'success')
    return redirect(url_for('login'))

@app.route('/admin_dashboard', methods=['GET', 'POST'])
@login_required
def admin_dashboard():
    if session.get('role') != 'admin':
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('jonyo_school.db')
    c = conn.cursor()
    
    # Fetch term information
    c.execute("PRAGMA table_info(term_info)")
    columns = [col[1] for col in c.fetchall()]
    if 'is_active' in columns:
        c.execute("SELECT term, start_date, end_date, principal_name FROM term_info WHERE is_active=1")
    else:
        c.execute("SELECT term, start_date, end_date, principal_name FROM term_info ORDER BY id DESC LIMIT 1")
    term_info = c.fetchone()
    
    # Fetch learners for dynamic admission number selection
    c.execute("SELECT admission_no, full_name FROM learners ORDER BY full_name")
    learners = c.fetchall()
    
    conn.close()
    
    current_year = datetime.now().year
    
    if request.method == 'POST':
        action = request.form.get('action')
        valid_terms = ['Term 1', 'Term 2', 'Term 3']
        valid_exam_types = ['Mid Term', 'End Term', 'CAT']  # Added CAT
        valid_grades = ['Grade 7', 'Grade 8', 'Grade 9']
        
        if action == 'preview_report_card':
            admission_no = request.form.get('admission_no')
            term = request.form.get('term')
            year = request.form.get('year')
            exam_type = request.form.get('exam_type')
            if not all([admission_no, term, year, exam_type]):
                flash('Missing required fields for report card preview.', 'danger')
            elif term not in valid_terms:
                flash('Invalid term selected.', 'danger')
            elif exam_type not in valid_exam_types:
                flash('Invalid exam type selected.', 'danger')
            else:
                try:
                    year = int(year)
                    if year < 2000 or year > current_year + 1:
                        raise ValueError
                    return redirect(url_for('preview_report_card', admission_no=admission_no, term=term, year=year, exam_type=exam_type))
                except ValueError:
                    flash('Invalid year entered.', 'danger')
        
        elif action == 'preview_fee_statement':
            admission_no = request.form.get('admission_no')
            if not admission_no:
                flash('Missing admission number for fee statement.', 'danger')
            else:
                return redirect(url_for('preview_fee_statement', admission_no=admission_no))
        
        elif action == 'view_class_exam_results':
            grade = request.form.get('grade')
            term = request.form.get('term')
            year = request.form.get('year')
            exam_type = request.form.get('exam_type')
            if not all([grade, term, year, exam_type]):
                flash('Missing required fields for exam results.', 'danger')
            elif grade not in valid_grades:
                flash('Invalid grade selected.', 'danger')
            elif term not in valid_terms:
                flash('Invalid term selected.', 'danger')
            elif exam_type not in valid_exam_types:
                flash('Invalid exam type selected.', 'danger')
            else:
                try:
                    year = int(year)
                    if year < 2000 or year > current_year + 1:
                        raise ValueError
                    return redirect(url_for('view_class_exam_results', grade=grade, term=term, year=year, exam_type=exam_type))
                except ValueError:
                    flash('Invalid year entered.', 'danger')
        
        elif 'formaction' in request.form:
            grade = request.form.get('grade')
            term = request.form.get('term')
            year = request.form.get('year')
            exam_type = request.form.get('exam_type')
            if not all([grade, term, year, exam_type]):
                flash('Missing required fields for download.', 'danger')
            elif grade not in valid_grades:
                flash('Invalid grade selected.', 'danger')
            elif term not in valid_terms:
                flash('Invalid term selected.', 'danger')
            elif exam_type not in valid_exam_types:
                flash('Invalid exam type selected.', 'danger')
            else:
                try:
                    year = int(year)
                    if year < 2000 or year > current_year + 1:
                        raise ValueError
                    formaction = request.form.get('formaction')
                    if formaction.endswith('download_results'):
                        return redirect(url_for('download_results', grade=grade, term=term, year=year, exam_type=exam_type))
                    elif formaction.endswith('download_report_cards'):
                        return redirect(url_for('download_report_cards', grade=grade, term=term, year=year, exam_type=exam_type))
                except ValueError:
                    flash('Invalid year entered.', 'danger')
    
    return render_template('admin_dashboard.html', term_info=term_info, learners=learners, current_year=current_year)

@login_manager.user_loader
def load_user(user_id):
    try:
        conn = sqlite3.connect('jonyo_school.db')
        c = conn.cursor()
        # Try users table first
        c.execute("SELECT id, username, role, full_name FROM users WHERE id=?", (user_id,))
        user_data = c.fetchone()
        if user_data:
            session['role'] = user_data[2]
            session['full_name'] = user_data[3]
            conn.close()
            return User(user_data[0], user_data[1], user_data[2], user_data[3])
        # Try learners table
        c.execute("SELECT admission_no, full_name, 'learner', full_name, grade FROM learners WHERE admission_no=?", (user_id,))
        learner_data = c.fetchone()
        if learner_data:
            session['role'] = learner_data[2]
            session['full_name'] = learner_data[3]
            session['grade'] = learner_data[4]
            conn.close()
            return User(learner_data[0], learner_data[1], learner_data[2], learner_data[3])
        conn.close()
        return None
    except sqlite3.Error as e:
        logging.error(f"Database error in load_user for user_id {user_id}: {str(e)}")
        return None

@app.route('/manage_users', methods=['GET', 'POST'])
@login_required
def manage_users():
    if current_user.role != 'admin':
        flash('Unauthorized access.', 'danger')
        logging.warning(f"Unauthorized manage_users access: user_id={current_user.id}")
        return redirect(url_for('login'))
    
    message_form = MessageForm()
    
    try:
        conn = sqlite3.connect('jonyo_school.db')
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        
        # Define all grades explicitly
        grades = ['Grade 7', 'Grade 8', 'Grade 9']
        
        # Fetch learning areas
        c.execute("SELECT id, name, grade FROM learning_areas ORDER BY grade, name")
        learning_areas = c.fetchall()
        
        # Fetch admin messages
        admin_messages = []
        try:
            c.execute("SELECT message, timestamp FROM messages WHERE sender_id=? AND receiver_id IS NULL ORDER BY timestamp DESC LIMIT 10", (current_user.id,))
            admin_messages = c.fetchall()
        except sqlite3.Error as e:
            flash(f'Error fetching messages: {str(e)}.', 'danger')
            logging.error(f"Error fetching messages: {str(e)}, user_id={current_user.id}")

        if request.method == 'POST':
            action = request.form.get('action')
            if action == 'register_teacher':
                full_name = request.form.get('full_name', '').strip()
                phone = request.form.get('phone', '').strip()
                assigned_learning_areas = request.form.getlist('learning_areas')
                if not full_name or len(full_name.split()) < 2:
                    flash('Full name must include at least first and last name.', 'danger')
                elif not (phone.isdigit() and len(phone) == 10 and phone.startswith('0')):
                    flash('Phone number must be 10 digits starting with 0.', 'danger')
                elif not assigned_learning_areas:
                    flash('At least one learning area must be assigned.', 'danger')
                else:
                    try:
                        username = full_name.lower().replace(' ', '') + ''.join(random.choices(string.digits, k=4))
                        c.execute("SELECT id FROM users WHERE username=?", (username,))
                        if c.fetchone():
                            flash('Generated username already exists. Try again.', 'danger')
                        else:
                            password = generate_teacher_password()
                            c.execute("INSERT INTO users (username, password, role, full_name, phone) VALUES (?, ?, ?, ?, ?)",
                                      (username, generate_password_hash(password), 'teacher', full_name, phone))
                            teacher_id = c.lastrowid
                            for la_id in assigned_learning_areas:
                                c.execute("SELECT grade FROM learning_areas WHERE id=?", (la_id,))
                                grade = c.fetchone()['grade']
                                c.execute("INSERT INTO teacher_assignments (teacher_id, grade, learning_area_id) VALUES (?, ?, ?)",
                                          (teacher_id, grade, la_id))
                            conn.commit()
                            flash(f'Teacher registered. Username: {username}, Password: {password}. Share securely.', 'success')
                            logging.info(f"Teacher registered: username={username}, teacher_id={teacher_id}, by admin={current_user.id}")
                    except sqlite3.Error as e:
                        conn.rollback()
                        flash(f'Database error registering teacher: {str(e)}', 'danger')
                        logging.error(f"Database error registering teacher: {str(e)}, username={username}")
            
            elif action == 'register_bursar':
                username = request.form.get('username', '').strip()
                full_name = request.form.get('full_name', '').strip()
                password = request.form.get('password', '')
                confirm_password = request.form.get('confirm_password', '')
                if not (username and full_name and password):
                    flash('All fields are required.', 'danger')
                elif not username.isalnum():
                    flash('Username must be alphanumeric.', 'danger')
                elif password != confirm_password:
                    flash('Passwords do not match.', 'danger')
                else:
                    try:
                        c.execute("SELECT id FROM users WHERE username=?", (username,))
                        if c.fetchone():
                            flash('Username already exists.', 'danger')
                        else:
                            c.execute("INSERT INTO users (username, password, role, full_name) VALUES (?, ?, ?, ?)",
                                      (username, generate_password_hash(password), 'bursar', full_name))
                            conn.commit()
                            flash('Bursar registered.', 'success')
                            logging.info(f"Bursar registered: username={username}, by admin={current_user.id}")
                    except sqlite3.Error as e:
                        conn.rollback()
                        flash(f'Database error registering bursar: {str(e)}', 'danger')
                        logging.error(f"Database error registering bursar: {str(e)}, username={username}")
            
            elif action == 'register_learner':
                full_name = request.form.get('full_name', '').strip()
                admission_no = request.form.get('admission_no', '').strip()
                grade = request.form.get('grade', '')
                parent_phone = request.form.get('parent_phone', '').strip() or None
                photo = request.files.get('photo')
                if not (full_name and admission_no and grade):
                    flash('Full name, admission number, and grade are required.', 'danger')
                elif grade not in grades:
                    flash('Invalid grade selected. Must be Grade 7, Grade 8, or Grade 9.', 'danger')
                elif parent_phone and not (parent_phone.isdigit() and len(parent_phone) == 10 and parent_phone.startswith('0')):
                    flash('Parent phone must be 10 digits starting with 0 or empty.', 'danger')
                else:
                    photo_path = 'N/A'
                    try:
                        if photo and allowed_file(photo.filename):
                            filename = f"{admission_no}_{uuid.uuid4()}.{photo.filename.rsplit('.', 1)[1].lower()}"
                            photo_path = os.path.join('static/photos', filename)
                            os.makedirs(os.path.join(app.root_path, 'static/photos'), exist_ok=True)
                            photo.save(os.path.join(app.root_path, photo_path))
                        c.execute("SELECT admission_no FROM learners WHERE admission_no=?", (admission_no,))
                        if c.fetchone():
                            flash('Admission number already exists.', 'danger')
                            if photo_path != 'N/A' and os.path.exists(os.path.join(app.root_path, photo_path)):
                                os.remove(os.path.join(app.root_path, photo_path))
                        else:
                            c.execute("INSERT INTO learners (full_name, admission_no, grade, parent_phone, photo_path) VALUES (?, ?, ?, ?, ?)",
                                      (full_name, admission_no, grade, parent_phone, photo_path))
                            if parent_phone:
                                c.execute("SELECT id FROM users WHERE phone=?", (parent_phone,))
                                parent = c.fetchone()
                                if parent:
                                    c.execute("INSERT INTO parent_learner (parent_id, learner_admission) VALUES (?, ?)",
                                              (parent['id'], admission_no))
                            conn.commit()
                            flash('Learner registered.', 'success')
                            logging.info(f"Learner registered: admission_no={admission_no}, grade={grade}, by admin={current_user.id}")
                    except sqlite3.Error as e:
                        conn.rollback()
                        flash(f'Database error registering learner: {str(e)}', 'danger')
                        logging.error(f"Database error registering learner: {str(e)}, admission_no={admission_no}")
                        if photo_path != 'N/A' and os.path.exists(os.path.join(app.root_path, photo_path)):
                            os.remove(os.path.join(app.root_path, photo_path))
            
            elif action == 'bulk_upload':
                grade = request.form.get('grade')
                file = request.files.get('file')
                logging.debug(f"Bulk upload: grade={grade}, file={file.filename if file else None}")
                if not (grade and file and allowed_file(file.filename)):
                    flash('Invalid grade or file type. Allowed: .csv, .xlsx, .xls', 'danger')
                    logging.error(f"Validation failed: grade={grade}, file={file.filename if file else None}, allowed={allowed_file(file.filename) if file else False}")
                elif grade not in grades:
                    flash('Invalid grade selected. Must be Grade 7, Grade 8, or Grade 9.', 'danger')
                    logging.error(f"Invalid grade: {grade}")
                else:
                    filename = f"{uuid.uuid4()}.{file.filename.rsplit('.', 1)[1].lower()}"
                    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    os.makedirs(os.path.dirname(os.path.join(app.root_path, file_path)), exist_ok=True)
                    file.save(os.path.join(app.root_path, file_path))
                    try:
                        learners_data = validate_learner_data(file_path, grade)
                        logging.debug(f"Learners data: {learners_data}")
                        for learner in learners_data:
                            if not (learner['admission_no'] and learner['full_name']):
                                flash(f"Invalid data for {learner['admission_no'] or 'unknown'}: Missing required fields.", 'danger')
                                continue
                            if learner['parent_phone'] and not (learner['parent_phone'].isdigit() and len(learner['parent_phone']) == 10 and learner['parent_phone'].startswith('0')):
                                flash(f"Invalid parent phone for {learner['admission_no']}: Must be 10 digits starting with 0.", 'danger')
                                continue
                            c.execute("SELECT admission_no FROM learners WHERE admission_no=?", (learner['admission_no'],))
                            if c.fetchone():
                                flash(f"Admission number {learner['admission_no']} already exists.", 'danger')
                                continue
                            photo_path = learner['photo_path']
                            if photo_path and photo_path != 'N/A' and os.path.exists(os.path.join(app.root_path, photo_path)):
                                filename = f"{learner['admission_no']}_{uuid.uuid4()}.{photo_path.rsplit('.', 1)[1].lower()}"
                                new_photo_path = os.path.join('static/photos', filename)
                                os.makedirs(os.path.join(app.root_path, 'static/photos'), exist_ok=True)
                                shutil.copy(os.path.join(app.root_path, photo_path), os.path.join(app.root_path, new_photo_path))
                                photo_path = new_photo_path
                            c.execute("INSERT INTO learners (full_name, admission_no, grade, parent_phone, photo_path) VALUES (?, ?, ?, ?, ?)",
                                      (learner['full_name'], learner['admission_no'], learner['grade'], learner['parent_phone'], photo_path))
                            if learner['parent_phone']:
                                c.execute("SELECT id FROM users WHERE phone=?", (learner['parent_phone'],))
                                parent = c.fetchone()
                                if parent:
                                    c.execute("INSERT INTO parent_learner (parent_id, learner_admission) VALUES (?, ?)",
                                              (parent['id'], learner['admission_no']))
                        conn.commit()
                        flash(f'Bulk upload completed. {len(learners_data)} learners processed.', 'success')
                        logging.info(f"Bulk upload of {len(learners_data)} learners for grade={grade}, by admin={current_user.id}")
                    except Exception as e:
                        conn.rollback()
                        flash(f'Error processing file: {str(e)}', 'danger')
                        logging.error(f"Error processing bulk upload: {str(e)}, grade={grade}, file={file_path}")
                    finally:
                        if os.path.exists(os.path.join(app.root_path, file_path)):
                            os.remove(os.path.join(app.root_path, file_path))
            
            elif action == 'delete_user':
                user_id = request.form.get('user_id')
                try:
                    c.execute("SELECT role FROM users WHERE id=?", (user_id,))
                    user = c.fetchone()
                    if not user:
                        flash('User not found.', 'danger')
                    elif user['role'] == 'admin' and current_user.id == int(user_id):
                        flash('Cannot delete your own admin account.', 'danger')
                    else:
                        c.execute("DELETE FROM users WHERE id=?", (user_id,))
                        if user['role'] == 'teacher':
                            c.execute("DELETE FROM teacher_assignments WHERE teacher_id=?", (user_id,))
                        conn.commit()
                        flash('User deleted.', 'success')
                        logging.info(f"User id={user_id} deleted by admin={current_user.id}")
                except sqlite3.Error as e:
                    conn.rollback()
                    flash(f'Database error deleting user: {str(e)}', 'danger')
                    logging.error(f"Database error deleting user id={user_id}: {str(e)}")
            
            elif action == 'delete_learner':
                admission_no = request.form.get('admission_no')
                try:
                    c.execute("SELECT admission_no, photo_path FROM learners WHERE admission_no=?", (admission_no,))
                    learner = c.fetchone()
                    if not learner:
                        flash('Learner not found.', 'danger')
                    else:
                        if learner['photo_path'] != 'N/A' and os.path.exists(os.path.join(app.root_path, learner['photo_path'])):
                            os.remove(os.path.join(app.root_path, learner['photo_path']))
                        c.execute("DELETE FROM learners WHERE admission_no=?", (admission_no,))
                        c.execute("DELETE FROM parent_learner WHERE learner_admission=?", (admission_no,))
                        conn.commit()
                        flash('Learner deleted.', 'success')
                        logging.info(f"Learner admission_no={admission_no} deleted by admin={current_user.id}")
                except sqlite3.Error as e:
                    conn.rollback()
                    flash(f'Database error deleting learner: {str(e)}', 'danger')
                    logging.error(f"Database error deleting learner admission_no={admission_no}: {str(e)}")
            
            elif action == 'update_learner':
                admission_no = request.form.get('admission_no')
                parent_phone = request.form.get('parent_phone', '').strip() or None
                photo = request.files.get('photo')
                try:
                    c.execute("SELECT admission_no, photo_path FROM learners WHERE admission_no=?", (admission_no,))
                    learner = c.fetchone()
                    if not learner:
                        flash('Learner not found.', 'danger')
                    elif parent_phone and not (parent_phone.isdigit() and len(parent_phone) == 10 and parent_phone.startswith('0')):
                        flash('Parent phone must be 10 digits starting with 0 or empty.', 'danger')
                    else:
                        photo_path = learner['photo_path']
                        if photo and allowed_file(photo.filename):
                            filename = f"{admission_no}_{uuid.uuid4()}.{photo.filename.rsplit('.', 1)[1].lower()}"
                            photo_path = os.path.join('static/photos', filename)
                            os.makedirs(os.path.join(app.root_path, 'static/photos'), exist_ok=True)
                            photo.save(os.path.join(app.root_path, photo_path))
                            if learner['photo_path'] != 'N/A' and os.path.exists(os.path.join(app.root_path, learner['photo_path'])):
                                os.remove(os.path.join(app.root_path, learner['photo_path']))
                        c.execute("UPDATE learners SET parent_phone=?, photo_path=? WHERE admission_no=?",
                                  (parent_phone, photo_path, admission_no))
                        if parent_phone:
                            c.execute("SELECT id FROM users WHERE phone=?", (parent_phone,))
                            parent = c.fetchone()
                            if parent:
                                c.execute("DELETE FROM parent_learner WHERE learner_admission=?", (admission_no,))
                                c.execute("INSERT INTO parent_learner (parent_id, learner_admission) VALUES (?, ?)",
                                          (parent['id'], admission_no))
                        conn.commit()
                        flash('Learner updated.', 'success')
                        logging.info(f"Learner admission_no={admission_no} updated by admin={current_user.id}")
                except sqlite3.Error as e:
                    conn.rollback()
                    flash(f'Database error updating learner: {str(e)}', 'danger')
                    logging.error(f"Database error updating learner admission_no={admission_no}: {str(e)}")
                    if photo_path != learner['photo_path'] and photo_path != 'N/A' and os.path.exists(os.path.join(app.root_path, photo_path)):
                        os.remove(os.path.join(app.root_path, photo_path))
            
            elif action == 'promote_learners':
                admission_nos = request.form.getlist('admission_nos')
                current_grade = request.form.get('current_grade')
                if not admission_nos or current_grade not in grades:
                    flash('No learners selected or invalid grade.', 'danger')
                else:
                    try:
                        next_grade = {'Grade 7': 'Grade 8', 'Grade 8': 'Grade 9'}.get(current_grade, current_grade)
                        c.executemany("UPDATE learners SET grade=? WHERE admission_no=?",
                                      [(next_grade, adm_no) for adm_no in admission_nos])
                        conn.commit()
                        flash(f'{len(admission_nos)} learner(s) promoted to {next_grade}.', 'success')
                        logging.info(f"{len(admission_nos)} learners promoted to {next_grade} by admin={current_user.id}")
                    except sqlite3.Error as e:
                        conn.rollback()
                        flash(f'Database error promoting learners: {str(e)}', 'danger')
                        logging.error(f"Database error promoting learners: {str(e)}")
            
            elif action == 'graduate_learners':
                admission_nos = request.form.getlist('admission_nos')
                if not admission_nos:
                    flash('No learners selected for graduation.', 'danger')
                else:
                    try:
                        current_year = datetime.now().year
                        for adm_no in admission_nos:
                            c.execute("SELECT full_name, admission_no, parent_phone, photo_path FROM learners WHERE admission_no=?", (adm_no,))
                            learner = c.fetchone()
                            if learner:
                                c.execute("INSERT INTO graduated_learners (full_name, admission_no, parent_phone, photo_path, graduation_year) VALUES (?, ?, ?, ?, ?)",
                                          (learner['full_name'], learner['admission_no'], learner['parent_phone'], learner['photo_path'], current_year))
                                c.execute("DELETE FROM learners WHERE admission_no=?", (adm_no,))
                                c.execute("DELETE FROM parent_learner WHERE learner_admission=?", (adm_no,))
                        conn.commit()
                        flash(f'{len(admission_nos)} learner(s) graduated.', 'success')
                        logging.info(f"{len(admission_nos)} learners graduated by admin={current_user.id}")
                    except sqlite3.Error as e:
                        conn.rollback()
                        flash(f'Database error graduating learners: {str(e)}', 'danger')
                        logging.error(f"Database error graduating learners: {str(e)}")
            
            elif action == 'send_admin_message':
                if message_form.validate_on_submit():
                    try:
                        c.execute("INSERT INTO messages (sender_id, message, timestamp) VALUES (?, ?, ?)",
                                  (current_user.id, message_form.message.data, datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
                        conn.commit()
                        flash('Message sent to all users.', 'success')
                        logging.info(f"Admin message sent by admin={current_user.id}")
                        c.execute("SELECT message, timestamp FROM messages WHERE sender_id=? AND receiver_id IS NULL ORDER BY timestamp DESC LIMIT 10", (current_user.id,))
                        admin_messages = c.fetchall()
                    except sqlite3.Error as e:
                        conn.rollback()
                        flash(f'Database error sending message: {str(e)}', 'danger')
                        logging.error(f"Database error sending admin message: {str(e)}")
                else:
                    flash('Invalid message.', 'danger')
        
        # Search and display users
        search_admin = request.args.get('search_admin', '')
        search_teacher = request.args.get('search_teacher', '')
        search_bursar = request.args.get('search_bursar', '')
        search_parent = request.args.get('search_parent', '')
        search_grade7 = request.args.get('search_grade7', '')
        search_grade8 = request.args.get('search_grade8', '')
        search_grade9 = request.args.get('search_grade9', '')
        promote_grade = request.args.get('promote_grade', '')
        
        try:
            c.execute("SELECT id, full_name FROM users WHERE role='admin' AND full_name LIKE ?", (f'%{search_admin}%',))
            admins = c.fetchall()
            c.execute("SELECT id, full_name FROM users WHERE role='teacher' AND full_name LIKE ?", (f'%{search_teacher}%',))
            teachers = c.fetchall()
            c.execute("SELECT id, full_name FROM users WHERE role='bursar' AND full_name LIKE ?", (f'%{search_bursar}%',))
            bursars = c.fetchall()
            c.execute("SELECT u.id, u.full_name, pl.learner_admission FROM users u LEFT JOIN parent_learner pl ON u.id=pl.parent_id WHERE u.role='parent' AND u.full_name LIKE ?", (f'%{search_parent}%',))
            parents = c.fetchall()
            
            def process_learners(raw_learners):
                learners = []
                os.makedirs(os.path.join(app.root_path, 'static/photos'), exist_ok=True)
                for learner in raw_learners:
                    admission_no = learner['admission_no']
                    full_name = learner['full_name']
                    parent_phone = learner['parent_phone']
                    photo_path = learner['photo_path']
                    if photo_path and photo_path != 'N/A' and os.path.exists(os.path.join(app.root_path, photo_path)):
                        if not photo_path.startswith('static/photos/'):
                            new_filename = f"{admission_no}_{os.path.basename(photo_path)}"
                            new_path = os.path.join('static/photos', new_filename)
                            try:
                                shutil.copy(os.path.join(app.root_path, photo_path), os.path.join(app.root_path, new_path))
                                c.execute("UPDATE learners SET photo_path=? WHERE admission_no=?", (new_path, admission_no))
                                conn.commit()
                                photo_path = new_path
                            except (OSError, IOError) as e:
                                logging.error(f"Failed to copy photo {photo_path} for {admission_no}: {str(e)}")
                                photo_path = 'N/A'
                    else:
                        photo_path = 'N/A'
                    learners.append({
                        'admission_no': admission_no,
                        'full_name': full_name,
                        'parent_phone': parent_phone,
                        'photo_path': photo_path
                    })
                return learners
            
            c.execute("SELECT admission_no, full_name, parent_phone, photo_path FROM learners WHERE grade='Grade 7' AND full_name LIKE ?", (f'%{search_grade7}%',))
            grade7 = process_learners(c.fetchall())
            c.execute("SELECT admission_no, full_name, parent_phone, photo_path FROM learners WHERE grade='Grade 8' AND full_name LIKE ?", (f'%{search_grade8}%',))
            grade8 = process_learners(c.fetchall())
            c.execute("SELECT admission_no, full_name, parent_phone, photo_path FROM learners WHERE grade='Grade 9' AND full_name LIKE ?", (f'%{search_grade9}%',))
            grade9 = process_learners(c.fetchall())
            promote_learners = []
            if promote_grade in grades:
                c.execute("SELECT admission_no, full_name, parent_phone, photo_path FROM learners WHERE grade=? AND full_name LIKE ?", (promote_grade, '%'))
                promote_learners = process_learners(c.fetchall())
        except sqlite3.Error as e:
            flash(f'Database error fetching users: {str(e)}', 'danger')
            logging.error(f"Database error fetching users: {str(e)}")
            admins = teachers = bursars = parents = grade7 = grade8 = grade9 = promote_learners = []
        
        conn.close()
        return render_template('manage_users.html',
                              admins=admins,
                              teachers=teachers,
                              bursars=bursars,
                              parents=parents,
                              grade7=grade7,
                              grade8=grade8,
                              grade9=grade9,
                              grades=grades,
                              learning_areas=learning_areas,
                              admin_messages=admin_messages,
                              message_form=message_form,
                              promote_grade=promote_grade,
                              promote_learners=promote_learners,
                              current_year=datetime.now().year)
    
    except sqlite3.Error as e:
        flash(f'Database connection error: {str(e)}', 'danger')
        logging.error(f"Database connection error in manage_users: {str(e)}")
        if 'conn' in locals():
            conn.close()
        return redirect(url_for('index')) 
@app.route('/edit_performance', methods=['GET', 'POST'])
@login_required
def edit_performance():
    if session.get('role') != 'admin':
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('jonyo_school.db')
    c = conn.cursor()
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        # Handle Subject-Level Performance
        if action == 'add_subject':
            min_mark = request.form.get('min_mark')
            max_mark = request.form.get('max_mark')
            level = request.form.get('level')
            points = request.form.get('points')
            comment = request.form.get('comment')
            if not all([min_mark, max_mark, level, points, comment]):
                flash('All fields are required for subject performance level.', 'danger')
            else:
                try:
                    c.execute("INSERT INTO performance_levels (min_mark, max_mark, level, points, comment) VALUES (?, ?, ?, ?, ?)",
                              (int(min_mark), int(max_mark), level, float(points), comment))
                    conn.commit()
                    flash('Subject performance level added successfully.', 'success')
                except ValueError:
                    flash('Invalid numeric values for min_mark, max_mark, or points.', 'danger')
                except sqlite3.IntegrityError:
                    flash('Overlapping or invalid range for subject performance level.', 'danger')
        
        elif action == 'update_subject':
            level_id = request.form.get('level_id')
            min_mark = request.form.get('min_mark')
            max_mark = request.form.get('max_mark')
            points = request.form.get('points')
            comment = request.form.get('comment')
            if level_id and min_mark and max_mark and points and comment:
                try:
                    c.execute("UPDATE performance_levels SET min_mark=?, max_mark=?, points=?, comment=? WHERE id=?",
                              (int(min_mark), int(max_mark), float(points), comment, int(level_id)))
                    conn.commit()
                    flash('Subject performance level updated successfully.', 'success')
                except ValueError:
                    flash('Invalid numeric values for min_mark, max_mark, or points.', 'danger')
        
        elif action == 'delete_subject':
            level_id = request.form.get('level_id')
            if level_id:
                c.execute("DELETE FROM performance_levels WHERE id=?", (int(level_id),))
                conn.commit()
                flash('Subject performance level deleted successfully.', 'success')
        
        # Handle Total Marks Performance
        elif action == 'add_total':
            min_total_marks = request.form.get('min_total_marks')
            max_total_marks = request.form.get('max_total_marks')
            grade = request.form.get('grade')
            points = request.form.get('points')
            comment = request.form.get('comment')
            if not all([min_total_marks, max_total_marks, grade, points, comment]):
                flash('All fields are required for total marks performance level.', 'danger')
            else:
                try:
                    c.execute("INSERT INTO total_marks_performance_levels (min_total_marks, max_total_marks, grade, points, comment) VALUES (?, ?, ?, ?, ?)",
                              (int(min_total_marks), int(max_total_marks), grade, float(points), comment))
                    conn.commit()
                    flash('Total marks performance level added successfully.', 'success')
                except ValueError:
                    flash('Invalid numeric values for min_total_marks, max_total_marks, or points.', 'danger')
                except sqlite3.IntegrityError:
                    flash('Overlapping or invalid range for total marks performance level.', 'danger')
        
        elif action == 'update_total':
            total_id = request.form.get('total_id')
            min_total_marks = request.form.get('min_total_marks')
            max_total_marks = request.form.get('max_total_marks')
            points = request.form.get('points')
            comment = request.form.get('comment')
            if total_id and min_total_marks and max_total_marks and points and comment:
                try:
                    c.execute("UPDATE total_marks_performance_levels SET min_total_marks=?, max_total_marks=?, points=?, comment=? WHERE id=?",
                              (int(min_total_marks), int(max_total_marks), float(points), comment, int(total_id)))
                    conn.commit()
                    flash('Total marks performance level updated successfully.', 'success')
                except ValueError:
                    flash('Invalid numeric values for min_total_marks, max_total_marks, or points.', 'danger')
        
        elif action == 'delete_total':
            total_id = request.form.get('total_id')
            if total_id:
                c.execute("DELETE FROM total_marks_performance_levels WHERE id=?", (int(total_id),))
                conn.commit()
                flash('Total marks performance level deleted successfully.', 'success')
    
    # Fetch data for display
    c.execute("SELECT id, min_mark, max_mark, level, points, comment FROM performance_levels ORDER BY min_mark")
    performance_levels = c.fetchall()
    
    c.execute("SELECT id, min_total_marks, max_total_marks, grade, points, comment FROM total_marks_performance_levels ORDER BY min_total_marks")
    total_marks_performance_levels = c.fetchall()
    
    conn.close()
    return render_template('edit_performance.html', 
                         performance_levels=performance_levels,
                         total_marks_performance_levels=total_marks_performance_levels)

@app.route('/manage_marks', methods=['GET', 'POST'])
@login_required
def manage_marks():
    logging.debug("Entering manage_marks route")
    
    # Check role with fallback
    role = session.get('role')
    if not role or role not in ['admin', 'teacher']:
        flash('Unauthorized access. Please log in again.', 'danger')
        logging.warning(f"Unauthorized access to manage_marks: user_id={session.get('user_id', 'unknown')}, role={role}")
        return redirect(url_for('login'))
    
    # Define valid grades and terms
    grades = ['Grade 7', 'Grade 8', 'Grade 9']
    terms = ['Term 1', 'Term 2', 'Term 3']
    
    # Initialize database connection
    conn = sqlite3.connect('jonyo_school.db')
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    
    try:
        # Fetch learning areas
        if role == 'teacher':
            c.execute("SELECT la.id, la.name, la.grade FROM learning_areas la JOIN teacher_assignments ta ON la.id=ta.learning_area_id WHERE ta.teacher_id=?",
                      (session['user_id'],))
        else:
            c.execute("SELECT id, name, grade FROM learning_areas")
        learning_areas = c.fetchall()
        logging.debug(f"Fetched {len(learning_areas)} learning areas")
    except sqlite3.Error as e:
        flash(f'Database error fetching learning areas: {str(e)}.', 'danger')
        logging.error(f"Error fetching learning areas: {str(e)}")
        conn.close()
        return redirect(url_for('manage_marks'))
    
    # Initialize form variables
    selected_grade = request.form.get('grade', grades[0])
    exam_type = request.form.get('exam_type', 'Mid Term')
    term = request.form.get('term', terms[0])
    year = request.form.get('year', str(datetime.now().year))
    cat_marks = request.form.get('cat_marks', 'no')
    search_learner = request.form.get('search_learner', '').strip()
    
    # Validate inputs
    valid_exam_types = ['Mid Term', 'End Term', 'CAT']
    if request.method == 'POST':
        if selected_grade not in grades:
            flash('Invalid grade selected.', 'danger')
            logging.error(f"Invalid grade selected: {selected_grade}")
            return redirect(url_for('manage_marks'))
        if exam_type not in valid_exam_types:
            flash('Invalid exam type selected.', 'danger')
            logging.error(f"Invalid exam type selected: {exam_type}")
            return redirect(url_for('manage_marks'))
        if term not in terms:
            flash('Invalid term selected.', 'danger')
            logging.error(f"Invalid term selected: {term}")
            return redirect(url_for('manage_marks'))
        try:
            year = int(year)
            if year < 2000 or year > datetime.now().year + 1:
                raise ValueError
        except ValueError:
            flash('Invalid year entered.', 'danger')
            logging.error(f"Invalid year entered: {year}")
            return redirect(url_for('manage_marks'))
    
    # Fetch students and existing marks
    students = []
    existing_marks = {}  # {admission_no: {learning_area_id: marks}}
    if selected_grade:
        try:
            query = "SELECT admission_no, full_name FROM learners WHERE grade=?"
            params = [selected_grade]
            if search_learner:
                query += " AND full_name LIKE ?"
                params.append(f'%{search_learner}%')
            c.execute(query, params)
            students = c.fetchall()
            logging.debug(f"Fetched {len(students)} students for grade {selected_grade}, term {term}")
            
            # Fetch existing marks for all learning areas
            c.execute("""
                SELECT m.learner_admission, m.learning_area_id, m.marks 
                FROM marks m
                JOIN learning_areas la ON m.learning_area_id=la.id
                WHERE m.exam_type=? AND m.term=? AND m.year=? AND m.grade=?
            """, (exam_type, term, year, selected_grade))
            marks_data = c.fetchall()
            for admission_no, la_id, marks in marks_data:
                if admission_no not in existing_marks:
                    existing_marks[admission_no] = {}
                existing_marks[admission_no][la_id] = marks
            logging.debug(f"Fetched existing marks: {len(marks_data)} entries")
        except sqlite3.Error as e:
            flash(f'Database error fetching students or marks: {str(e)}.', 'danger')
            logging.error(f"Error fetching students/marks: {str(e)}")
    
    # Submit marks
    if request.method == 'POST' and 'submit_marks' in request.form:
        updated_count = 0
        try:
            for student in students:
                for la_id, la_name, la_grade in learning_areas:
                    if la_grade != selected_grade:
                        continue
                    marks = request.form.get(f'marks_{student["admission_no"]}_{la_id}')
                    if marks is None or marks.strip() == '':
                        continue  # Skip if no marks provided
                    try:
                        marks = int(marks)
                        if not (0 <= marks <= 100):
                            flash(f'Invalid marks for {student["full_name"]} in {la_name}. Marks must be between 0 and 100.', 'danger')
                            continue
                        
                        # Fetch points from performance_levels
                        c.execute("SELECT points FROM performance_levels WHERE ? BETWEEN min_mark AND max_mark", (marks,))
                        points = c.fetchone()
                        points = points[0] if points else 0
                        
                        # Handle End Term with CAT marks
                        total_marks = marks
                        if exam_type == 'End Term' and cat_marks == 'yes':
                            c.execute("SELECT marks FROM marks WHERE learner_admission=? AND learning_area_id=? AND exam_type='CAT' AND term=? AND year=?",
                                      (student["admission_no"], la_id, term, year))
                            cat = c.fetchone()
                            if not cat:
                                flash(f'No CAT marks found for {student["full_name"]} in {la_name}, {term} {year}. Using raw marks.', 'warning')
                            else:
                                total_marks = int(cat[0]) + marks
                                if total_marks > 100:
                                    flash(f'Total marks for {student["full_name"]} in {la_name} exceed 100. Adjusted to 100.', 'warning')
                                    total_marks = 100
                                c.execute("SELECT points FROM performance_levels WHERE ? BETWEEN min_mark AND max_mark", (total_marks,))
                                points = c.fetchone()
                                points = points[0] if points else 0
                        
                        # Check if marks already exist
                        c.execute("""
                            SELECT marks FROM marks 
                            WHERE learner_admission=? AND learning_area_id=? AND exam_type=? AND term=? AND year=?
                        """, (student["admission_no"], la_id, exam_type, term, year))
                        existing = c.fetchone()
                        if existing:
                            logging.info(f"Updating marks for learner {student['admission_no']} in {la_name}: {existing[0]} to {total_marks}")
                        else:
                            logging.info(f"Inserting new marks for learner {student['admission_no']} in {la_name}: {total_marks}")
                        
                        # Insert or update marks
                        c.execute("""
                            INSERT OR REPLACE INTO marks 
                            (learner_admission, learning_area_id, marks, exam_type, term, year, points, grade) 
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """, (student["admission_no"], la_id, total_marks, exam_type, term, year, points, selected_grade))
                        updated_count += 1
                    except ValueError:
                        flash(f'Invalid marks for {student["full_name"]} in {la_name}. Marks must be numeric.', 'danger')
                        logging.warning(f"Invalid marks input for {student['full_name']} in {la_name}: {marks}")
                        continue
            
            if updated_count > 0:
                conn.commit()
                flash(f'Marks submitted successfully for {updated_count} entries.', 'success')
                logging.info(f"Submitted {updated_count} marks entries for grade {selected_grade}, term {term}, year {year}")
            else:
                flash('No valid marks were submitted.', 'warning')
        except sqlite3.Error as e:
            conn.rollback()
            flash(f'Database error submitting marks: {str(e)}.', 'danger')
            logging.error(f"Error submitting marks: {str(e)}")
        
        # Redirect after submission
        logging.debug("Marks submitted, returning to manage_marks")
        conn.close()
        return redirect(url_for('manage_marks'))
    
    # Render template
    logging.debug("Rendering manage_marks.html")
    response = render_template('manage_marks.html',
                              grades=grades,
                              learning_areas=learning_areas,
                              students=students,
                              existing_marks=existing_marks,
                              selected_grade=selected_grade,
                              exam_type=exam_type,
                              term=term,
                              terms=terms,
                              year=year,
                              cat_marks=cat_marks,
                              search_learner=search_learner,
                              current_year=datetime.now().year)
    logging.debug("manage_marks route completed successfully")
    conn.close()
    return response

@app.route('/manage_fees', methods=['GET', 'POST'])
@login_required
def manage_fees():
    if session.get('role') not in ['admin', 'bursar']:
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('jonyo_school.db')
    c = conn.cursor()
    grades = ['Grade 7', 'Grade 8', 'Grade 9']
    
    # Fetch active terms
    terms = []
    try:
        c.execute("PRAGMA table_info(term_info)")
        columns = [col[1] for col in c.fetchall()]
        if 'is_active' in columns:
            c.execute("SELECT term FROM term_info WHERE is_active=1")
        else:
            c.execute("SELECT term FROM term_info ORDER BY id DESC LIMIT 1")
        terms = [row[0] for row in c.fetchall()]
    except sqlite3.Error as e:
        flash(f'Database error fetching terms: {str(e)}', 'danger')
        print(f"Error fetching terms: {str(e)}")
    
    # Default values
    selected_grade = request.form.get('grade', grades[0])
    term = request.form.get('term', terms[0] if terms else 'Term 1')
    year = request.form.get('year', str(datetime.now().year))
    students = []
    
    if request.method == 'POST' and request.form.get('submit_fees'):
        grade = request.form.get('grade')
        term = request.form.get('term')
        year = request.form.get('year')
        if not (grade in grades and term in terms and year.isdigit()):
            flash('Invalid grade, term, or year.', 'danger')
        else:
            try:
                year = int(year)
                for key in request.form:
                    if key.startswith('total_fee_'):
                        adm_no = key[len('total_fee_'):]
                        try:
                            total_fee = int(request.form.get(f'total_fee_{adm_no}', 0))
                            amount_paid = int(request.form.get(f'amount_paid_{adm_no}', 0))
                            if total_fee < 0 or amount_paid < 0:
                                flash(f'Invalid fees for {adm_no}: Fees cannot be negative.', 'danger')
                                continue
                            balance = total_fee - amount_paid
                            if balance < 0:
                                flash(f'Invalid fees for {adm_no}: Amount paid exceeds total fee.', 'danger')
                                continue
                            c.execute("INSERT OR REPLACE INTO fees (learner_admission, grade, total_fee, amount_paid, balance, term, year) VALUES (?, ?, ?, ?, ?, ?, ?)",
                                      (adm_no, grade, total_fee, amount_paid, balance, term, year))
                        except ValueError:
                            flash(f'Invalid input for {adm_no}: Fees must be numeric.', 'danger')
                            continue
                conn.commit()
                flash('Fees submitted successfully.', 'success')
            except sqlite3.Error as e:
                flash(f'Database error submitting fees: {str(e)}', 'danger')
                print(f"Error submitting fees: {str(e)}")
    
    # Fetch students for selected grade
    if selected_grade in grades:
        try:
            c.execute("SELECT admission_no, full_name FROM learners WHERE grade=?", (selected_grade,))
            students = c.fetchall()
        except sqlite3.Error as e:
            flash(f'Database error fetching students: {str(e)}', 'danger')
            print(f"Error fetching students: {str(e)}")
    
    # Handle fee statement download
    if request.args.get('download') == 'true':
        try:
            c.execute("""
                SELECT DISTINCT l.admission_no, l.full_name, f.grade, f.term, f.year, f.total_fee, f.amount_paid, f.balance
                FROM learners l
                LEFT JOIN fees f ON l.admission_no = f.learner_admission 
                                 AND f.grade = ? 
                                 AND f.term = ? 
                                 AND f.year = ?
                WHERE l.grade = ?
                ORDER BY l.full_name
            """, (selected_grade, term, year, selected_grade))
            fee_data = c.fetchall()
            
            if not fee_data:
                flash('No fee data available for download.', 'warning')
                return render_template('manage_fees.html', 
                                      grades=grades, 
                                      terms=terms, 
                                      selected_grade=selected_grade, 
                                      term=term, 
                                      year=year, 
                                      students=students,
                                      current_year=datetime.now().year)
            
            # Create DataFrame
            df = pd.DataFrame(fee_data, columns=['Admission No', 'Full Name', 'Grade', 'Term', 'Year', 'Total Fee', 'Amount Paid', 'Balance'])
            
            # Export to Excel with shortened worksheet name
            output = io.BytesIO()
            grade_short = selected_grade[-1]  # e.g., '7' from 'Grade 7'
            term_short = term[-1] if term.startswith('Term') else term  # e.g., '1' from 'Term 1'
            sheet_name = f'Fees_G{grade_short}_T{term_short}_{year}'
            with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
                df.to_excel(writer, sheet_name=sheet_name, index=False)
                worksheet = writer.sheets[sheet_name]
                worksheet.set_column(0, 0, 15)  # Admission No
                worksheet.set_column(1, 1, 25)  # Full Name
                worksheet.set_column(2, 2, 10)  # Grade
                worksheet.set_column(3, 3, 10)  # Term
                worksheet.set_column(4, 4, 10)  # Year
                worksheet.set_column(5, 5, 12)  # Total Fee
                worksheet.set_column(6, 6, 12)  # Amount Paid
                worksheet.set_column(7, 7, 12)  # Balance
            
            output.seek(0)
            logging.info(f"Fee statement downloaded for grade={selected_grade}, term={term}, year={year} by user_id={session.get('user_id')}")
            conn.close()
            return send_file(output, as_attachment=True, download_name=f"fee_statement_{selected_grade}_{term}_{year}.xlsx", mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
        except sqlite3.Error as e:
            flash(f'Database error generating fee statement: {str(e)}', 'danger')
            print(f"Error generating fee statement: {str(e)}")
        except Exception as e:
            flash(f'Error generating fee statement: {str(e)}', 'danger')
            print(f"Error generating fee statement: {str(e)}")
        conn.close()
        return render_template('manage_fees.html', 
                              grades=grades, 
                              terms=terms, 
                              selected_grade=selected_grade, 
                              term=term, 
                              year=year, 
                              students=students,
                              current_year=datetime.now().year)
    
    conn.close()
    return render_template('manage_fees.html', 
                          grades=grades, 
                          terms=terms, 
                          selected_grade=selected_grade, 
                          term=term, 
                          year=year, 
                          students=students,
                          current_year=datetime.now().year)
    

@app.route('/upload_notes', methods=['GET', 'POST'])
@login_required
def upload_notes():
    logging.debug(f"Entering upload_notes route: user_id={current_user.id}, role={session.get('role')}")
    
    # Check role
    role = session.get('role')
    if not role or role not in ['admin', 'teacher']:
        flash('Unauthorized access. Please log in again.', 'danger')
        logging.warning(f"Unauthorized access to upload_notes: user_id={session.get('user_id', 'unknown')}, role={role}")
        return redirect(url_for('login'))
    
    # Initialize database connection
    db_path = 'C:/Users/USER/Desktop/jonyo school/jonyo_school.db'
    logging.debug(f"Connecting to database: {db_path}")
    if not os.path.exists(db_path):
        flash(f'Database file not found: {db_path}', 'danger')
        logging.error(f"Database file not found: {db_path}")
        return redirect(url_for('index'))
    
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    
    grades = ['Grade 7', 'Grade 8', 'Grade 9']
    
    try:
        # Check if teacher_notes table exists
        c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='teacher_notes'")
        if not c.fetchone():
            flash('Teacher_notes table does not exist in the database.', 'danger')
            logging.error(f"Teacher_notes table missing in database: {db_path}")
            conn.close()
            return redirect(url_for('index'))
        
        # Fetch learning areas
        learning_areas = []
        if role == 'teacher':
            c.execute("SELECT la.id, la.name, la.grade FROM learning_areas la JOIN teacher_assignments ta ON la.id=ta.learning_area_id WHERE ta.teacher_id=?", (current_user.id,))
            learning_areas = c.fetchall()
            if not learning_areas:
                logging.warning(f"No teacher assignments for teacher_id={current_user.id}. Falling back to all learning areas.")
                c.execute("SELECT id, name, grade FROM learning_areas")
                learning_areas = c.fetchall()
        else:
            c.execute("SELECT id, name, grade FROM learning_areas")
            learning_areas = c.fetchall()
        
        logging.debug(f"Fetched {len(learning_areas)} learning areas: {[dict(area) for area in learning_areas]}")
        
        # Check if learning areas are available
        if not learning_areas:
            flash('No learning areas available. Please contact the admin to add learning areas.', 'warning')
            logging.warning(f"No learning areas found for role={role}, user_id={current_user.id}")
            conn.close()
            return render_template('upload_notes.html',
                                  grades=grades,
                                  learning_areas=learning_areas,
                                  notes=[],
                                  role=role)
        
        # Fetch existing notes
        if role == 'admin':
            c.execute("SELECT n.id, n.grade, la.name, n.file_path, n.upload_date, u.full_name, n.downloads FROM teacher_notes n JOIN learning_areas la ON n.learning_area_id=la.id JOIN users u ON n.uploaded_by=u.id")
        else:
            c.execute("SELECT n.id, n.grade, la.name, n.file_path, n.upload_date, u.full_name, n.downloads FROM teacher_notes n JOIN learning_areas la ON n.learning_area_id=la.id JOIN users u ON n.uploaded_by=u.id WHERE n.uploaded_by=?",
                      (current_user.id,))
        notes = c.fetchall()
        logging.debug(f"Fetched {len(notes)} notes")
        
        if request.method == 'POST':
            grade = request.form.get('grade')
            learning_area_id = request.form.get('learning_area_id')
            file = request.files.get('file')
            
            logging.debug(f"Form data: grade={grade}, learning_area_id={learning_area_id}, file={file.filename if file else None}")
            
            # Detailed validation
            if not grade:
                flash('Please select a grade.', 'danger')
                logging.error(f"Missing grade: grade={grade}")
            elif not learning_area_id or not learning_area_id.isdigit():
                flash('Please select a learning area.', 'danger')
                logging.error(f"Invalid or missing learning_area_id: learning_area_id={learning_area_id}")
            elif not file or not file.filename:
                flash('Please upload a file.', 'danger')
                logging.error(f"Missing file: file={file}")
            elif not allowed_file(file.filename):
                flash(f'Invalid file type: {file.filename}. Allowed: .pdf, .doc, .docx', 'danger')
                logging.error(f"Invalid file type: filename={file.filename}")
            elif grade not in grades:
                flash(f'Invalid grade selected: {grade}', 'danger')
                logging.error(f"Invalid grade: grade={grade}")
            else:
                try:
                    # Verify learning area
                    c.execute("SELECT id, grade FROM learning_areas WHERE id=?", (learning_area_id,))
                    la = c.fetchone()
                    if not la or la['grade'] != grade:
                        flash('Invalid learning area for selected grade.', 'danger')
                        logging.error(f"Invalid learning area: id={learning_area_id}, grade={grade}")
                    else:
                        # Save file
                        filename = f"{current_user.id}_{grade}_{learning_area_id}_{datetime.now().strftime('%Y%m%d%H%M%S')}.{file.filename.rsplit('.', 1)[1].lower()}"
                        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                        os.makedirs(os.path.dirname(file_path), exist_ok=True)
                        file.save(file_path)
                        
                        # Insert note
                        c.execute("INSERT INTO teacher_notes (grade, learning_area_id, file_path, upload_date, uploaded_by, downloads) VALUES (?, ?, ?, ?, ?, ?)",
                                  (grade, learning_area_id, file_path, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), current_user.id, ''))
                        conn.commit()
                        flash('Notes uploaded successfully.', 'success')
                        logging.info(f"Notes uploaded: grade={grade}, learning_area_id={learning_area_id}, file={file_path}, by user={current_user.id}")
                        return redirect(url_for('upload_notes'))
                except sqlite3.Error as e:
                    conn.rollback()
                    flash(f'Database error uploading notes: {str(e)}.', 'danger')
                    logging.error(f"Database error uploading notes: {str(e)}")
                except OSError as e:
                    flash(f'Error saving file: {str(e)}.', 'danger')
                    logging.error(f"File save error: {str(e)}")
        
        conn.close()
        return render_template('upload_notes.html',
                              grades=grades,
                              learning_areas=learning_areas,
                              notes=notes,
                              role=role)
    
    except sqlite3.Error as e:
        flash(f'Database connection error: {str(e)}.', 'danger')
        logging.error(f"Database connection error in upload_notes: {str(e)}, db_path={db_path}")
        if 'conn' in locals():
            conn.close()
        return redirect(url_for('index'))
    
@app.route('/online_exam', methods=['GET', 'POST'])
@login_required
def online_exam():
    form = ExamForm()
    # Debug form fields
    print("Form fields:", form._fields.keys())  # Print to terminal
    logging.debug(f"Form fields: {form._fields.keys()}")
    if 'exam_name' not in form._fields:
        logging.error("ExamForm is missing 'exam_name' field")
    
    grades = ['Grade 7', 'Grade 8', 'Grade 9']
    nairobi_tz = pytz.timezone('Africa/Nairobi')
    
    try:
        with sqlite3.connect('C:/Users/USER/Desktop/jonyo school/jonyo_school.db') as conn:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()

            # Delete expired exams on page load (for admins/teachers)
            if current_user.role in ['admin', 'teacher']:
                deleted_count = delete_expired_exams_route()
                if isinstance(deleted_count, int) and deleted_count > 0:
                    flash(f'Deleted {deleted_count} expired exam(s).', 'info')
                elif not isinstance(deleted_count, int):
                    logging.error(f"delete_expired_exams_route returned unexpected type: {type(deleted_count)}")
                    flash('Error processing expired exams.', 'danger')

            # Fetch learning areas
            try:
                if current_user.role == 'teacher':
                    c.execute("SELECT learning_area_id FROM teacher_assignments WHERE teacher_id=?", (current_user.id,))
                    area_ids = [row['learning_area_id'] for row in c.fetchall()]
                    if area_ids:
                        c.execute("SELECT id, name FROM learning_areas WHERE id IN ({})".format(','.join('?'*len(area_ids))), area_ids)
                    else:
                        c.execute("SELECT id, name FROM learning_areas")
                else:
                    c.execute("SELECT id, name FROM learning_areas")
                learning_areas = c.fetchall()
                form.learning_area.choices = [(str(area['id']), area['name']) for area in learning_areas]
                if not learning_areas:
                    flash('No learning areas available. Please contact the admin.', 'warning')
                    logging.warning(f"No learning areas found for role={current_user.role}, user_id={current_user.id}")
            except Exception as e:
                flash(f'Database error fetching learning areas: {str(e)}', 'danger')
                logging.error(f"Error fetching learning areas: {str(e)}, user_id={current_user.id}")
                learning_areas = []

            # Handle exam selection for learners (GET with exam_id)
            exam_id = request.args.get('exam_id')
            questions = None
            exam_name = None
            exam_grade = None
            if current_user.role == 'learner' and exam_id:
                try:
                    c.execute("SELECT grade FROM learners WHERE admission_no=?", (current_user.username,))
                    learner_grade = c.fetchone()
                    if not learner_grade:
                        flash('Learner profile not found', 'danger')
                        logging.error(f"Learner profile not found: admission_no={current_user.username}")
                        return redirect(url_for('learner_dashboard'))
                    learner_grade = learner_grade['grade']
                    c.execute("SELECT id, learning_area_id, start_time, end_time, exam_name FROM exams WHERE id=? AND grade=? AND is_active=1", (exam_id, learner_grade))
                    exam = c.fetchone()
                    if exam:
                        now = datetime.now(nairobi_tz)
                        start = nairobi_tz.localize(datetime.strptime(exam['start_time'], '%Y-%m-%d %H:%M:%S')) if exam['start_time'] else now
                        end = nairobi_tz.localize(datetime.strptime(exam['end_time'], '%Y-%m-%d %H:%M:%S')) if exam['end_time'] else now
                        if start <= now <= end:
                            c.execute("SELECT id, question_text FROM exam_questions WHERE exam_id=?", (exam['id'],))
                            questions = c.fetchall()
                            c.execute("SELECT name FROM learning_areas WHERE id=?", (exam['learning_area_id'],))
                            area_name = c.fetchone()['name']
                            exam_name = exam['exam_name'] or f"{area_name} Exam"
                            exam_grade = learner_grade
                            logging.info(f"Exam accessed: id={exam_id}, learner={current_user.username}, grade={learner_grade}")
                        else:
                            flash(f'Exam is not available. Available from {exam["start_time"]} to {exam["end_time"]}', 'danger')
                    else:
                        flash('Exam not found or not available for your grade', 'danger')
                except (ValueError, Exception) as e:
                    flash(f'Error loading exam: {str(e)}', 'danger')
                    logging.error(f"Error loading exam {exam_id}: {str(e)}, user_id={current_user.id}")
                    return redirect(url_for('learner_dashboard'))

            if request.method == 'POST':
                if current_user.role in ['admin', 'teacher']:
                    logging.debug(f"POST Form fields: {form._fields.keys()}")
                    if form.validate_on_submit():
                        try:
                            if form.is_online.data == '1' and not any([form.question_1.data, form.question_2.data, form.question_3.data, form.question_4.data, form.question_5.data]):
                                flash('At least one question is required for online exams', 'danger')
                                return redirect(url_for('online_exam'))
                            file_path = None
                            if form.file.data and allowed_file(form.file.data.filename):
                                filename = secure_filename(form.file.data.filename)
                                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                                os.makedirs(os.path.dirname(file_path), exist_ok=True)
                                form.file.data.save(file_path)
                            c.execute("SELECT name FROM learning_areas WHERE id=?", (form.learning_area.data,))
                            area_name = c.fetchone()['name']
                            exam_name = form.exam_name.data or f"{area_name} Exam {form.grade.data}"
                            start_time = datetime.strptime(form.start_time.data, '%Y-%m-%d %H:%M:%S')
                            end_time = datetime.strptime(form.end_time.data, '%Y-%m-%d %H:%M:%S')
                            c.execute('''INSERT INTO exams (uploaded_by, grade, learning_area_id, file_path, start_time, end_time, is_online, exam_name, is_active)
                                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                                      (current_user.id, form.grade.data, form.learning_area.data, file_path,
                                       start_time.strftime('%Y-%m-%d %H:%M:%S'), 
                                       end_time.strftime('%Y-%m-%d %H:%M:%S'), 
                                       int(form.is_online.data), exam_name, 1))
                            exam_id = c.lastrowid
                            questions = [form.question_1.data, form.question_2.data, form.question_3.data, form.question_4.data, form.question_5.data]
                            for q in questions:
                                if q and q.strip():
                                    c.execute("INSERT INTO exam_questions (exam_id, question_text) VALUES (?, ?)", (exam_id, q.strip()))
                            conn.commit()
                            flash('Online exam created successfully', 'success')
                            logging.info(f"Exam created: id={exam_id}, by user_id={current_user.id}, grade={form.grade.data}, learning_area={area_name}")
                            return redirect(url_for('online_exam'))
                        except ValueError as e:
                            conn.rollback()
                            flash(f'Invalid date format: {str(e)}', 'danger')
                            logging.error(f"Invalid date format in exam creation: {str(e)}, input_start={form.start_time.data}, input_end={form.end_time.data}, user_id={current_user.id}")
                            return redirect(url_for('online_exam'))
                        except Exception as e:
                            conn.rollback()
                            flash(f'Error creating exam: {str(e)}', 'danger')
                            logging.error(f"Error creating exam: {str(e)}, user_id={current_user.id}")
                            return redirect(url_for('online_exam'))
                    else:
                        logging.debug(f"Form validation failed: {form.errors}")
                        flash('Form validation failed. Please check all required fields.', 'danger')
                elif current_user.role == 'learner':
                    exam_id = request.form.get('exam_id')
                    try:
                        c.execute("SELECT start_time, end_time, is_active FROM exams WHERE id=?", (exam_id,))
                        exam = c.fetchone()
                        if not exam or exam['is_active'] != 1:
                            flash('Exam not found or inactive', 'danger')
                            return redirect(url_for('learner_dashboard'))
                        now = datetime.now(nairobi_tz)
                        start = nairobi_tz.localize(datetime.strptime(exam['start_time'], '%Y-%m-%d %H:%M:%S')) if exam['start_time'] else now
                        end = nairobi_tz.localize(datetime.strptime(exam['end_time'], '%Y-%m-%d %H:%M:%S')) if exam['end_time'] else now
                        if start <= now <= end:
                            c.execute("SELECT COUNT(*) FROM exam_answers WHERE exam_id=? AND learner_admission=?", (exam_id, current_user.username))
                            if c.fetchone()['COUNT(*)'] > 0:
                                flash('You have already submitted this exam', 'warning')
                                return redirect(url_for('learner_dashboard'))
                            for i in range(1, 6):
                                answer = request.form.get(f'answer_{i}')
                                question_id = request.form.get(f'question_id_{i}')
                                if answer and question_id:
                                    c.execute('''INSERT INTO exam_answers (exam_id, learner_admission, question_id, answer_text, submitted_at)
                                                 VALUES (?, ?, ?, ?, ?)''',
                                              (exam_id, current_user.username, question_id, answer, now.strftime('%Y-%m-%d %H:%M:%S')))
                            conn.commit()
                            flash('Exam submitted successfully', 'success')
                            logging.info(f"Exam submitted: id={exam_id}, by learner={current_user.username}")
                        else:
                            flash(f'Exam is not available. Available from {exam["start_time"]} to {exam["end_time"]}', 'danger')
                        return redirect(url_for('learner_dashboard'))
                    except (ValueError, Exception) as e:
                        conn.rollback()
                        flash(f'Error submitting exam: {str(e)}', 'danger')
                        logging.error(f"Error submitting exam {exam_id}: {str(e)}, user_id={current_user.id}")
                        return redirect(url_for('learner_dashboard'))

            # Fetch exams with submission status
            exams = []
            submission_status = {}
            expired_status = {}
            try:
                if current_user.role == 'learner' and not questions:
                    c.execute("SELECT grade FROM learners WHERE admission_no=?", (current_user.username,))
                    learner_grade = c.fetchone()
                    if learner_grade:
                        c.execute("""
                            SELECT e.id, e.grade, e.learning_area_id, e.start_time, e.end_time, e.exam_name, l.name 
                            FROM exams e 
                            JOIN learning_areas l ON e.learning_area_id=l.id 
                            WHERE e.grade=? AND e.is_active=1
                        """, (learner_grade['grade'],))
                        exams = c.fetchall()
                        logging.info(f"Fetched {len(exams)} exams for learner {current_user.username}, grade={learner_grade['grade']}")
                        now = datetime.now(nairobi_tz)
                        for exam in exams:
                            c.execute("SELECT COUNT(*) FROM exam_answers WHERE exam_id=? AND learner_admission=?", (exam['id'], current_user.username))
                            submission_status[exam['id']] = c.fetchone()['COUNT(*)'] > 0
                            end_time = nairobi_tz.localize(datetime.strptime(exam['end_time'], '%Y-%m-%d %H:%M:%S'))
                            expired_status[exam['id']] = end_time < now
                elif current_user.role in ['admin', 'teacher']:
                    if current_user.role == 'admin':
                        c.execute("""
                            SELECT e.id, e.grade, e.learning_area_id, e.start_time, e.end_time, e.exam_name, l.name 
                            FROM exams e 
                            JOIN learning_areas l ON e.learning_area_id=l.id 
                            JOIN users u ON e.uploaded_by=u.id
                        """)
                    else:
                        c.execute("""
                            SELECT e.id, e.grade, e.learning_area_id, e.start_time, e.end_time, e.exam_name, l.name 
                            FROM exams e 
                            JOIN learning_areas l ON e.learning_area_id=l.id 
                            JOIN users u ON e.uploaded_by=u.id 
                            WHERE e.uploaded_by=?
                        """, (current_user.id,))
                    exams = c.fetchall()
                    now = datetime.now(nairobi_tz)
                    for exam in exams:
                        end_time = nairobi_tz.localize(datetime.strptime(exam['end_time'], '%Y-%m-%d %H:%M:%S'))
                        expired_status[exam['id']] = end_time < now
            except Exception as e:
                flash(f'Database error fetching exams: {str(e)}', 'danger')
                logging.error(f"Error fetching exams: {str(e)}, user_id={current_user.id}")
                exams = []

            # Fetch exam takers for admins/teachers
            exam_takers = []
            if current_user.role in ['admin', 'teacher']:
                try:
                    if current_user.role == 'teacher':
                        c.execute("""
                            SELECT ea.exam_id, ea.learner_admission, ea.question_id, ea.answer_text, ea.submitted_at, l.full_name 
                            FROM exam_answers ea 
                            JOIN learners l ON ea.learner_admission=l.admission_no 
                            JOIN exams e ON ea.exam_id=e.id 
                            WHERE e.uploaded_by=?
                        """, (current_user.id,))
                    else:
                        c.execute("""
                            SELECT ea.exam_id, ea.learner_admission, ea.question_id, ea.answer_text, ea.submitted_at, l.full_name 
                            FROM exam_answers ea 
                            JOIN learners l ON ea.learner_admission=l.admission_no
                        """)
                    exam_takers = c.fetchall()
                except Exception as e:
                    flash(f'Database error fetching exam takers: {str(e)}', 'danger')
                    logging.error(f"Error fetching exam takers: {str(e)}, user_id={current_user.id}")
                    exam_takers = []

            return render_template('online_exam.html',
                                 form=form,
                                 grades=grades,
                                 learning_areas=learning_areas,
                                 exams=exams,
                                 exam_takers=exam_takers,
                                 role=current_user.role,
                                 questions=questions,
                                 exam_id=exam_id,
                                 exam_name=exam_name,
                                 exam_grade=exam_grade,
                                 submission_status=submission_status,
                                 expired_status=expired_status,
                                 current_year=datetime.now().year)

    except sqlite3.Error as e:
        flash(f'Database error: {str(e)}', 'danger')
        logging.error(f"Database error in online_exam: {str(e)}, user_id={current_user.id}")
        return redirect(url_for('learner_dashboard' if current_user.role == 'learner' else 'admin_dashboard' if current_user.role == 'admin' else 'teacher_dashboard'))
@app.route('/delete_exam/<int:exam_id>', methods=['GET'])
@login_required
def delete_exam(exam_id):
    # Verify delete token
    provided_token = request.args.get('token', '')
    expected_token = hashlib.md5(f"{current_user.id}{app.config['SECRET_KEY']}{int(time.time())//3600}".encode()).hexdigest()
    if provided_token != expected_token:
        flash('Invalid or expired delete token.', 'danger')
        logging.warning(f"Invalid delete token for exam_id={exam_id}, provided={provided_token}, expected={expected_token}, user_id={current_user.id}, role={current_user.role}")
        return redirect(url_for('online_exam'))

    if current_user.role not in ['admin', 'teacher']:
        flash('Unauthorized access.', 'danger')
        logging.warning(f"Unauthorized exam deletion attempt: exam_id={exam_id}, user_id={current_user.id}, role={current_user.role}")
        return redirect(url_for('login'))

    try:
        with sqlite3.connect('jonyo_school.db') as conn:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            # Check exam exists and get end_time
            c.execute("SELECT file_path, exam_name, uploaded_by, end_time FROM online_exams WHERE id=? AND is_active=1", (exam_id,))
            exam = c.fetchone()
            if not exam:
                flash('Exam not found or already deleted.', 'danger')
                logging.warning(f"Exam not found for deletion: exam_id={exam_id}, user_id={current_user.id}, role={current_user.role}")
                return redirect(url_for('online_exam'))
            if current_user.role == 'teacher' and exam['uploaded_by'] != current_user.id:
                flash('You can only delete exams you created.', 'danger')
                logging.warning(f"Teacher unauthorized deletion attempt: exam_id={exam_id}, exam_name={exam['exam_name']}, user_id={current_user.id}")
                return redirect(url_for('online_exam'))

            # Check if exam is expired
            nairobi_tz = pytz.timezone('Africa/Nairobi')
            now = datetime.now(nairobi_tz)
            end_time = nairobi_tz.localize(datetime.strptime(exam['end_time'], '%Y-%m-%d %H:%M:%S'))
            if end_time >= now:
                flash('Cannot delete active exam. Only expired exams can be deleted.', 'danger')
                logging.warning(f"Attempt to delete active exam: exam_id={exam_id}, exam_name={exam['exam_name']}, end_time={exam['end_time']}, user_id={current_user.id}")
                return redirect(url_for('online_exam'))

            # Delete associated file
            if exam['file_path'] and os.path.exists(exam['file_path']):
                try:
                    os.remove(exam['file_path'])
                    logging.info(f"Deleted file: {exam['file_path']} for exam_id={exam_id}")
                except OSError as e:
                    logging.error(f"Error deleting file {exam['file_path']}: {str(e)}")

            # Delete exam data
            c.execute("DELETE FROM exam_questions WHERE exam_id=?", (exam_id,))
            c.execute("DELETE FROM exam_submissions WHERE exam_id=?", (exam_id,))
            c.execute("DELETE FROM online_exams WHERE id=?", (exam_id,))
            conn.commit()
            flash('Exam deleted successfully.', 'success')
            logging.info(f"Exam deleted: id={exam_id}, exam_name={exam['exam_name']}, by user_id={current_user.id}, role={current_user.role}")
    except sqlite3.Error as e:
        flash(f'Error deleting exam: {str(e)}', 'danger')
        logging.error(f"Error deleting exam {exam_id}: {str(e)}, user_id={current_user.id}, role={current_user.role}")
    return redirect(url_for('online_exam'))


@app.route('/delete_expired_exams', methods=['POST'])
@login_required
def delete_expired_exams_route():
    if current_user.role not in ['admin', 'teacher']:
        logging.warning(f"Unauthorized expired exams deletion attempt: user_id={current_user.id}, role={current_user.role}")
        raise ValueError("Unauthorized access")

    try:
        deleted_count = delete_expired_exams()
        logging.info(f"Manual expired exams deletion triggered: {deleted_count} exams deleted, by user_id={current_user.id}, role={current_user.role}")
        return deleted_count
    except Exception as e:
        logging.error(f"Error in delete_expired_exams_route: {str(e)}, user_id={current_user.id}")
        raise

@app.route('/generate_report_card', methods=['GET', 'POST'])
@login_required
def generate_report_card():
    if session.get('role') not in ['admin', 'teacher', 'parent']:
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        admission_no = request.form.get('admission_no')
        term = request.form.get('term')
        year = request.form.get('year')
        exam_type = request.form.get('exam_type')
    else:
        admission_no = request.args.get('admission_no')
        term = request.args.get('term')
        year = request.args.get('year')
        exam_type = request.args.get('exam_type')
    
    if not all([admission_no, term, year, exam_type]):
        flash('Missing required parameters.', 'danger')
        return redirect(url_for(f"{session['role']}_dashboard"))
    
    conn = sqlite3.connect('jonyo_school.db')
    c = conn.cursor()
    
    # Validate inputs
    valid_terms = ['Term 1', 'Term 2', 'Term 3']
    valid_exam_types = ['Mid Term', 'End Term', 'CAT']
    if term not in valid_terms or exam_type not in valid_exam_types:
        conn.close()
        flash('Invalid term or exam type.', 'danger')
        return redirect(url_for(f"{session['role']}_dashboard"))
    
    try:
        year = int(year)
        if year < 2000 or year > datetime.now().year + 1:
            raise ValueError
    except ValueError:
        conn.close()
        flash('Invalid year.', 'danger')
        return redirect(url_for(f"{session['role']}_dashboard"))
    
    # Fetch learner details
    c.execute("SELECT full_name, grade FROM learners WHERE admission_no=?", (admission_no,))
    learner = c.fetchone()
    if not learner:
        conn.close()
        flash('Learner not found.', 'danger')
        return redirect(url_for(f"{session['role']}_dashboard"))
    
    full_name, grade = learner
    
    # Fetch marks with performance levels
    try:
        # Main marks (Mid Term, End Term, or CAT)
        c.execute("""
            SELECT la.id, la.name, m.marks, pl.points, pl.level, pl.comment
            FROM marks m
            JOIN learning_areas la ON m.learning_area_id=la.id
            JOIN performance_levels pl ON m.marks BETWEEN pl.min_mark AND pl.max_mark
            WHERE m.learner_admission=? AND m.term=? AND m.year=? AND m.grade=? AND m.exam_type=?
            ORDER BY la.name
        """, (admission_no, term, year, grade, exam_type))
        marks = c.fetchall()
        
        # Fetch CAT marks for End Term
        cat_marks = {}
        if exam_type == 'End Term':
            c.execute("""
                SELECT la.name, m.marks
                FROM marks m
                JOIN learning_areas la ON m.learning_area_id=la.id
                WHERE m.learner_admission=? AND m.term=? AND m.year=? AND m.grade=? AND m.exam_type='CAT'
                ORDER BY la.name
            """, (admission_no, term, year, grade))
            cat_marks = {row[0]: row[1] for row in c.fetchall()}
    except sqlite3.OperationalError as e:
        conn.close()
        flash(f'Database error: {str(e)}. Please ensure the database schema is up to date.', 'danger')
        return redirect(url_for(f"{session['role']}_dashboard"))
    
    if not marks:
        conn.close()
        flash(f'No marks found for {full_name} in {term} {year} ({exam_type}).', 'warning')
        return redirect(url_for(f"{session['role']}_dashboard"))
    
    # Calculate total marks and grade
    total_marks = sum(mark[2] for mark in marks) if marks else 0
    c.execute("""
        SELECT grade, comment
        FROM total_marks_performance_levels
        WHERE ? BETWEEN min_total_marks AND max_total_marks
    """, (total_marks,))
    total_grade_info = c.fetchone()
    total_grade = total_grade_info[0] if total_grade_info else 'N/A'
    total_comment = total_grade_info[1] if total_grade_info else 'N/A'
    
    # Calculate total points
    total_points = sum(mark[3] for mark in marks) if marks else 0
    
    # Fetch total learners and calculate rank
    c.execute("SELECT COUNT(*) FROM learners WHERE grade=?", (grade,))
    total_learners = c.fetchone()[0]
    
    c.execute('''SELECT m.learner_admission, SUM(m.marks) as total_marks 
                 FROM marks m 
                 WHERE m.grade=? AND m.term=? AND m.year=? AND m.exam_type=? 
                 GROUP BY m.learner_admission''',
              (grade, term, year, exam_type))
    totals = c.fetchall()
    sorted_totals = sorted(totals, key=lambda x: x[1] or 0, reverse=True)
    rank_dict = {adm_no: i + 1 for i, (adm_no, _) in enumerate(sorted_totals)}
    rank = rank_dict.get(admission_no, 'N/A')
    
    # Fetch fees
    c.execute("SELECT total_fee, balance FROM fees WHERE learner_admission=? AND term=? AND year=?",
              (admission_no, term, year))
    fee_data = c.fetchone()
    total_fee = fee_data[0] if fee_data else 0
    balance = fee_data[1] if fee_data else 0
    
    # Fetch teacher assignments
    c.execute("SELECT learning_area_id, u.full_name FROM teacher_assignments ta JOIN users u ON ta.teacher_id = u.id")
    teacher_assignments = dict(c.fetchall())
    
    # Fetch class teacher
    c.execute("SELECT u.full_name FROM class_teachers ct JOIN users u ON ct.teacher_id=u.id WHERE ct.grade=?", (grade,))
    class_teacher_result = c.fetchone()
    class_teacher = class_teacher_result[0] if class_teacher_result else 'Not Assigned'
    
    # Fetch principal name from term_info
    c.execute("SELECT principal_name FROM term_info WHERE term=? AND start_date LIKE ?",
              (term, f'{year}%'))
    result = c.fetchone()
    principal_name = result[0] if result else 'Not Set'
    
    conn.close()
    
    # Generate PDF
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, topMargin=0.5*inch, bottomMargin=0.5*inch)
    elements = []
    styles = getSampleStyleSheet()
    header_style = ParagraphStyle(name='Header', fontSize=16, fontName='Helvetica-Bold', alignment=TA_CENTER, spaceAfter=12)
    centered_style = ParagraphStyle(name='Centered', parent=styles['Normal'], alignment=TA_CENTER, spaceAfter=6)
    
    # Watermark
    with tempfile.TemporaryDirectory() as tmpdir:
        watermark = Image.new('RGBA', (200, 100), (255, 255, 255, 0))
        draw = ImageDraw.Draw(watermark)
        try:
            font = ImageFont.truetype("arial.ttf", 20)
        except:
            font = ImageFont.load_default()
        draw.text((10, 40), "Jonyo Junior Secondary", fill=(0, 0, 0, 128), font=font)
        watermark_path = os.path.join(tmpdir, 'watermark.png')
        watermark.save(watermark_path)
        
        def add_watermark(canvas, doc):
            canvas.saveState()
            canvas.setFillAlpha(0.2)
            canvas.drawImage(watermark_path, 200, 400, width=200, height=100)
            canvas.restoreState()
        
        # Header
        elements.append(Paragraph("Jonyo Junior Secondary School", header_style))
        elements.append(Paragraph("Report Card", header_style))
        elements.append(Paragraph(f"Name: {full_name}", centered_style))
        elements.append(Paragraph(f"Admission No: {admission_no}", centered_style))
        elements.append(Paragraph(f"Grade: {grade} | Term: {term} | Year: {year} | Exam: {exam_type}", centered_style))
        elements.append(Spacer(1, 0.2 * inch))
        
        # Marks table
        headers = ['Learning Areas', 'Marks', 'Performance Levels', 'Points', 'Comment', 'Teacher']
        if exam_type == 'End Term' and cat_marks:
            headers.insert(1, 'CAT Marks')
        
        data = [headers]
        for mark in marks:
            la_id, la_name, mark_value, points, level, comment = mark
            teacher_name = teacher_assignments.get(la_id, 'Not Assigned')
            row = [la_name, str(mark_value) if mark_value else '', level, str(points) if points else 'N/A', comment, teacher_name]
            if exam_type == 'End Term' and cat_marks:
                cat_mark = cat_marks.get(la_name, 'N/A')
                row.insert(1, str(cat_mark))
            data.append(row)
        
        col_widths = [1.5*inch, 0.8*inch, 1.0*inch, 0.8*inch, 1.5*inch, 1.2*inch]
        if exam_type == 'End Term' and cat_marks:
            col_widths.insert(1, 0.8*inch)
        
        table = Table(data, colWidths=col_widths)
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        elements.append(table)
        
        # Footer
        elements.append(Spacer(1, 0.2 * inch))
        elements.append(Paragraph(f"Total Marks: {total_marks}", styles['Normal']))
        elements.append(Paragraph(f"Grade: {total_grade} ({total_comment})", styles['Normal']))
        elements.append(Paragraph(f"Points: {total_points}", styles['Normal']))
        elements.append(Paragraph(f"Rank: {rank} out of {total_learners}", styles['Normal']))
        elements.append(Paragraph(f"Total Fee: {total_fee}", styles['Normal']))
        elements.append(Paragraph(f"Balance: {balance}", styles['Normal']))
        elements.append(Paragraph("Class Teacher Comment: Keep up the good work.", styles['Normal']))
        elements.append(Paragraph(f"Principal Comment: Continue to strive for excellence. - {principal_name}", styles['Normal']))
        elements.append(Paragraph(f"Class Teacher Signature: Signed: {class_teacher}", styles['Normal']))
        elements.append(Paragraph(f"Principal Signature: Signed: {principal_name}", styles['Normal']))
        elements.append(Spacer(1, 0.2 * inch))
        elements.append(Paragraph("School Stamp:", styles['Normal']))
        stamp_table = Table([['']], colWidths=[1*inch], rowHeights=[0.5*inch])
        stamp_table.setStyle(TableStyle([('GRID', (0, 0), (-1, -1), 1, colors.black)]))
        elements.append(stamp_table)
        elements.append(Paragraph(f"Generated on: {datetime.now(pytz.timezone('Africa/Nairobi')).strftime('%Y-%m-%d')}", styles['Normal']))
        
        doc.build(elements, onFirstPage=add_watermark, onLaterPages=add_watermark)
    
    buffer.seek(0)
    logging.info(f"Report card generated for admission_no={admission_no}, term={term}, year={year}, exam_type={exam_type} by user_id={session.get('user_id')}")
    return send_file(buffer, as_attachment=True, download_name=f"report_card_{admission_no}_{term}_{year}_{exam_type}.pdf")


@app.route('/report_card/<admission_no>/<term>/<year>/<exam_type>')
@login_required
def report_card(admission_no, term, year, exam_type):
    if session.get('role') not in ['admin', 'learner', 'parent']:
        flash('Unauthorized access. Please log in with appropriate role.', 'danger')
        logging.warning(f"Unauthorized access to report_card: role={session.get('role')}, admission_no={admission_no}, session={session}")
        session.clear()
        return redirect(url_for('login'))
    
    if session.get('role') == 'learner' and admission_no != session.get('user_id'):
        flash('Access denied. You can only view your own report card.', 'danger')
        logging.warning(f"Unauthorized report card access: user_id={session.get('user_id')}, requested={admission_no}")
        return redirect(url_for('learner_dashboard'))
    
    try:
        year = int(year)
        if year < 2000 or year > datetime.now().year + 1:
            raise ValueError("Year out of valid range")
    except ValueError:
        flash('Invalid year. Please select a valid year.', 'danger')
        logging.warning(f"Invalid year in report_card: year={year}, admission_no={admission_no}")
        return redirect(url_for(f"{session['role']}_dashboard"))
    
    try:
        with sqlite3.connect('jonyo_school.db') as conn:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            
            # Verify learner
            c.execute("SELECT full_name, grade, photo_path FROM learners WHERE admission_no=?", (admission_no,))
            learner = c.fetchone()
            if not learner:
                flash('Learner not found. Contact admin at rolexoshia@gmail.com or 0114745401.', 'danger')
                logging.error(f"Learner not found in report_card: admission_no={admission_no}, session={session}")
                return redirect(url_for(f"{session['role']}_dashboard"))
            
            full_name = learner['full_name']
            grade = learner['grade']
            photo_path = learner['photo_path'] or 'N/A'
            
            # Check if marks table exists
            c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='marks'")
            if not c.fetchone():
                flash('Marks table not available. Contact admin at rolexoshia@gmail.com.', 'warning')
                logging.warning(f"Marks table missing for report_card: admission_no={admission_no}")
                return render_template('report_card.html',
                                     full_name=full_name,
                                     admission_no=admission_no,
                                     term=term,
                                     year=year,
                                     exam_type=exam_type,
                                     grade=grade,
                                     photo_path=photo_path,
                                     marks=[],
                                     total_marks=0,
                                     total_grade='N/A',
                                     total_comment='N/A',
                                     total_fee=0,
                                     balance=0,
                                     rank='N/A',
                                     total_learners=0,
                                     total_points=0,
                                     class_teacher_name='Not Assigned',
                                     principal_name='Not Set',
                                     current_year=datetime.now().year,
                                     current_date=datetime.now(pytz.timezone('Africa/Nairobi')).strftime('%Y-%m-%d'))
            
            # Fetch marks (case-insensitive, deduplicated)
            c.execute("""
                SELECT DISTINCT la.name AS subject, m.marks
                FROM marks m
                JOIN learning_areas la ON m.learning_area_id = la.id
                WHERE m.learner_admission = ?
                AND UPPER(m.term) = UPPER(?)
                AND m.year = ?
                AND UPPER(m.exam_type) = UPPER(?)
                ORDER BY la.name
            """, (admission_no, term, year, exam_type))
            marks = c.fetchall()
            
            # Fetch CAT marks for End Term
            cat_marks = {}
            if exam_type.lower() == 'end term':
                c.execute("""
                    SELECT DISTINCT la.name, m.marks 
                    FROM marks m 
                    JOIN learning_areas la ON m.learning_area_id = la.id 
                    WHERE m.learner_admission = ?
                    AND UPPER(m.term) = UPPER(?)
                    AND m.year = ?
                    AND UPPER(m.exam_type) = 'CAT'
                    ORDER BY la.name
                """, (admission_no, term, year))
                cat_marks = {row['name']: row['marks'] for row in c.fetchall()}
            
            # Log query results
            logging.info(f"Report card query for {admission_no}: term={term}, year={year}, exam_type={exam_type}, marks={[(row['subject'], row['marks']) for row in marks]}, cat_marks={cat_marks}")
            
            if not marks:
                flash(f'No marks found for {full_name} in {term} {year} ({exam_type}). Contact admin at rolexoshia@gmail.com or 0114745401 if this is incorrect.', 'warning')
                logging.warning(f"No marks found: admission_no={admission_no}, term={term}, year={year}, exam_type={exam_type}")
                return render_template('report_card.html',
                                     full_name=full_name,
                                     admission_no=admission_no,
                                     term=term,
                                     year=year,
                                     exam_type=exam_type,
                                     grade=grade,
                                     photo_path=photo_path,
                                     marks=[],
                                     total_marks=0,
                                     total_grade='N/A',
                                     total_comment='N/A',
                                     total_fee=0,
                                     balance=0,
                                     rank='N/A',
                                     total_learners=0,
                                     total_points=0,
                                     class_teacher_name='Not Assigned',
                                     principal_name='Not Set',
                                     current_year=datetime.now().year,
                                     current_date=datetime.now(pytz.timezone('Africa/Nairobi')).strftime('%Y-%m-%d'))
            
            # Prepare marks data
            total_marks = sum(mark['marks'] for mark in marks)
            total_points = 0
            marks_list = []
            for mark in marks:
                # Fetch performance level
                c.execute("""
                    SELECT level, points, comment 
                    FROM performance_levels 
                    WHERE ? BETWEEN min_mark AND max_mark
                """, (mark['marks'],))
                perf = c.fetchone()
                performance_level = perf['level'] if perf else 'N/A'
                points = perf['points'] if perf else 0
                comment = perf['comment'] if perf else 'N/A'
                total_points += points
                
                # Fetch teacher
                c.execute("""
                    SELECT u.full_name 
                    FROM teacher_assignments ta 
                    JOIN users u ON ta.teacher_id = u.id 
                    WHERE ta.learning_area_id = (SELECT id FROM learning_areas WHERE name = ?)
                """, (mark['subject'],))
                teacher = c.fetchone()
                teacher_name = teacher['full_name'] if teacher else 'Not Assigned'
                
                marks_list.append({
                    'marks': mark['marks'],
                    'learning_area': mark['subject'],
                    'performance_level': performance_level,
                    'points': points,
                    'comment': comment,
                    'teacher': teacher_name,
                    'cat_marks': cat_marks.get(mark['subject'], 'N/A') if exam_type.lower() == 'end term' else None
                })
            
            # Fetch total grade
            c.execute("""
                SELECT grade, comment 
                FROM total_marks_performance_levels 
                WHERE ? BETWEEN min_total_marks AND max_total_marks
            """, (total_marks,))
            total_grade_info = c.fetchone()
            total_grade = total_grade_info['grade'] if total_grade_info else 'N/A'
            total_comment = total_grade_info['comment'] if total_grade_info else 'N/A'
            
            # Fetch fees
            c.execute("SELECT total_fee, balance FROM fees WHERE learner_admission=? AND term=? AND year=?",
                      (admission_no, term, year))
            fee = c.fetchone()
            total_fee = fee['total_fee'] if fee else 0
            balance = fee['balance'] if fee else 0
            
            # Fetch total learners and rank
            c.execute("SELECT COUNT(*) FROM learners WHERE grade=?", (grade,))
            total_learners = c.fetchone()[0]
            
            c.execute("""
                SELECT m.learner_admission, SUM(m.marks) as total_marks 
                FROM marks m 
                WHERE m.grade=? AND UPPER(m.term)=UPPER(?) AND m.year=? AND UPPER(m.exam_type)=UPPER(?) 
                GROUP BY m.learner_admission
            """, (grade, term, year, exam_type))
            totals = c.fetchall()
            sorted_totals = sorted(totals, key=lambda x: x['total_marks'] or 0, reverse=True)
            rank_dict = {adm_no: i + 1 for i, (adm_no, _) in enumerate(sorted_totals)}
            rank = rank_dict.get(admission_no, 'N/A')
            
            # Fetch class teacher
            c.execute("SELECT u.full_name FROM class_teachers ct JOIN users u ON ct.teacher_id=u.id WHERE ct.grade=?", (grade,))
            class_teacher = c.fetchone()
            class_teacher_name = class_teacher['full_name'] if class_teacher else 'Not Assigned'
            
            # Fetch principal
            c.execute("SELECT principal_name FROM term_info WHERE term=? AND start_date LIKE ?", (term, f'{year}%'))
            principal = c.fetchone()
            principal_name = principal['principal_name'] if principal else 'Not Set'
            
            # Check if DOCX download is requested
            if request.args.get('download') == 'true':
                doc = Document()
                doc.add_heading('Jonyo Junior Secondary School', 0).alignment = 1
                doc.add_heading('Report Card', 1).alignment = 1
                if photo_path != 'N/A' and os.path.exists(os.path.join(app.root_path, photo_path)):
                    try:
                        doc.add_picture(os.path.join(app.root_path, photo_path), width=Inches(1), height=Inches(1)).alignment = 2
                    except:
                        pass
                doc.add_paragraph(f"Name: {full_name}", style='Normal').alignment = 1
                doc.add_paragraph(f"Admission No: {admission_no}", style='Normal').alignment = 1
                doc.add_paragraph(f"Grade: {grade} | Term: {term} | Year: {year} | Exam: {exam_type}", style='Normal').alignment = 1
                doc.add_paragraph()
                
                # Marks table
                headers = ['Learning Area', 'Marks', 'Performance Level', 'Points', 'Comment', 'Teacher']
                if exam_type.lower() == 'end term':
                    headers.insert(1, 'CAT Marks')
                table = doc.add_table(rows=1, cols=len(headers))
                table.style = 'Table Grid'
                for i, header in enumerate(headers):
                    table.rows[0].cells[i].text = header
                    table.rows[0].cells[i].paragraphs[0].runs[0].bold = True
                for mark in marks_list:
                    row = table.add_row().cells
                    row[0].text = mark['learning_area']
                    if exam_type.lower() == 'end term':
                        row[1].text = str(mark['cat_marks'])
                        row[2].text = str(mark['marks'])
                        row[3].text = mark['performance_level']
                        row[4].text = str(mark['points'])
                        row[5].text = mark['comment']
                        row[6].text = mark['teacher']
                    else:
                        row[1].text = str(mark['marks'])
                        row[2].text = mark['performance_level']
                        row[3].text = str(mark['points'])
                        row[4].text = mark['comment']
                        row[5].text = mark['teacher']
                
                # Footer
                doc.add_paragraph()
                doc.add_paragraph(f"Total Marks: {total_marks}", style='Normal')
                doc.add_paragraph(f"Grade: {total_grade} ({total_comment})", style='Normal')
                doc.add_paragraph(f"Points: {total_points}", style='Normal')
                doc.add_paragraph(f"Rank: {rank} out of {total_learners}", style='Normal')
                doc.add_paragraph(f"Total Fee: {total_fee}", style='Normal')
                doc.add_paragraph(f"Balance: {balance}", style='Normal')
                doc.add_paragraph("Class Teacher Comment: Keep up the good work.", style='Normal')
                doc.add_paragraph(f"Principal Comment: Continue to strive for excellence. - {principal_name}", style='Normal')
                doc.add_paragraph(f"Class Teacher Signature: Signed: {class_teacher_name}", style='Normal')
                doc.add_paragraph(f"Principal Signature: Signed: {principal_name}", style='Normal')
                doc.add_paragraph("School Stamp: ____________________", style='Normal')
                doc.add_paragraph(f"Generated on: {datetime.now(pytz.timezone('Africa/Nairobi')).strftime('%Y-%m-%d')}", style='Normal')
                
                output = io.BytesIO()
                doc.save(output)
                output.seek(0)
                logging.info(f"Report card DOCX generated for admission_no={admission_no}, term={term}, year={year}, exam_type={exam_type} by user_id={session.get('user_id')}")
                return send_file(output, download_name=f"report_card_{admission_no}_{term}_{year}_{exam_type}.docx", as_attachment=True)
            
            return render_template('report_card.html',
                                 full_name=full_name,
                                 admission_no=admission_no,
                                 grade=grade,
                                 photo_path=photo_path,
                                 term=term,
                                 year=year,
                                 exam_type=exam_type,
                                 marks=marks_list,
                                 total_marks=total_marks,
                                 total_grade=total_grade,
                                 total_comment=total_comment,
                                 total_fee=total_fee,
                                 balance=balance,
                                 rank=rank,
                                 total_learners=total_learners,
                                 total_points=total_points,
                                 class_teacher_name=class_teacher_name,
                                 principal_name=principal_name,
                                 current_year=datetime.now().year,
                                 current_date=datetime.now(pytz.timezone('Africa/Nairobi')).strftime('%Y-%m-%d'))
    
    except sqlite3.Error as e:
        flash(f'Database error occurred. Contact admin at rolexoshia@gmail.com or 0114745401.', 'danger')
        logging.error(f"Database error in report_card for {admission_no}: {str(e)}, term={term}, year={year}, exam_type={exam_type}, session={session}")
        return render_template('report_card.html',
                             full_name=full_name or 'Unknown',
                             admission_no=admission_no,
                             term=term,
                             year=year,
                             exam_type=exam_type,
                             grade=grade or 'Unknown',
                             photo_path=photo_path,
                             marks=[],
                             total_marks=0,
                             total_grade='N/A',
                             total_comment='N/A',
                             total_fee=0,
                             balance=0,
                             rank='N/A',
                             total_learners=0,
                             total_points=0,
                             class_teacher_name='Not Assigned',
                             principal_name='Not Set',
                             current_year=datetime.now().year,
                             current_date=datetime.now(pytz.timezone('Africa/Nairobi')).strftime('%Y-%m-%d'))

@app.route('/download_report_cards', methods=['POST'])
@login_required
def download_report_cards():
    logging.debug("Entering download_report_cards route")
    
    if session.get('role') != 'admin':
        flash('Unauthorized access.', 'danger')
        logging.warning(f"Unauthorized access to download_report_cards: user_id={session.get('user_id', 'unknown')}, role={session.get('role', 'unknown')}")
        return redirect(url_for('login'))
    
    exam_type = request.form.get('exam_type')
    grade = request.form.get('grade')
    term = request.form.get('term')
    year = request.form.get('year')
    
    if not all([exam_type, grade, term, year]) or \
       exam_type not in ['Mid Term', 'End Term', 'CAT'] or \
       grade not in ['Grade 7', 'Grade 8', 'Grade 9'] or \
       term not in ['Term 1', 'Term 2', 'Term 3']:
        flash('Invalid exam type, grade, term, or year.', 'danger')
        logging.error(f"Invalid input: exam_type={exam_type}, grade={grade}, term={term}, year={year}")
        return redirect(url_for('admin_dashboard'))
    
    try:
        year = int(year)
        if year < 2000 or year > datetime.now().year + 1:
            raise ValueError
    except ValueError:
        flash('Invalid year.', 'danger')
        logging.error(f"Invalid year: year={year}")
        return redirect(url_for('admin_dashboard'))
    
    conn = sqlite3.connect('jonyo_school.db')
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    
    # Fetch learners
    c.execute("SELECT admission_no, full_name FROM learners WHERE grade=?", (grade,))
    learners = c.fetchall()
    if not learners:
        conn.close()
        flash('No learners found for the selected grade.', 'warning')
        logging.warning(f"No learners found for grade={grade}")
        return redirect(url_for('admin_dashboard'))
    logging.debug(f"Fetched {len(learners)} learners for grade {grade}")
    
    # Fetch learning areas
    c.execute("SELECT id, name FROM learning_areas WHERE grade=?", (grade,))
    learning_areas = c.fetchall()
    if not learning_areas:
        conn.close()
        flash('No learning areas found for this grade.', 'danger')
        logging.error(f"No learning areas found for grade={grade}")
        return redirect(url_for('admin_dashboard'))
    area_ids = [area['id'] for area in learning_areas]
    area_names = [area['name'] for area in learning_areas]
    logging.debug(f"Fetched {len(area_names)} learning areas")
    
    # Fetch performance levels
    c.execute("SELECT min_mark, max_mark, level, points, comment FROM performance_levels")
    performance_levels = c.fetchall()
    if not performance_levels:
        conn.close()
        flash('Performance levels not configured.', 'danger')
        logging.error("Performance levels not found in database")
        return redirect(url_for('admin_dashboard'))
    
    # Fetch total marks performance levels
    c.execute("SELECT min_total_marks, max_total_marks, grade, comment FROM total_marks_performance_levels")
    total_performance_levels = c.fetchall()
    if not total_performance_levels:
        conn.close()
        flash('Total marks performance levels not configured.', 'danger')
        logging.error("Total marks performance levels not found in database")
        return redirect(url_for('admin_dashboard'))
    
    # Fetch teacher assignments
    c.execute("SELECT learning_area_id, u.full_name FROM teacher_assignments ta JOIN users u ON ta.teacher_id = u.id")
    teacher_assignments = dict(c.fetchall())
    logging.debug(f"Fetched teacher assignments: {len(teacher_assignments)} entries")
    
    # Fetch class teacher
    c.execute("SELECT u.full_name FROM class_teachers ct JOIN users u ON ct.teacher_id=u.id WHERE ct.grade=?", (grade,))
    class_teacher_result = c.fetchone()
    class_teacher = class_teacher_result['full_name'] if class_teacher_result else 'Not Assigned'
    
    # Fetch principal name from term_info
    c.execute("SELECT principal_name FROM term_info WHERE term=? AND start_date LIKE ?",
              (term, f'{year}%'))
    result = c.fetchone()
    principal_name = result['principal_name'] if result else 'Not Set'
    
    # Calculate ranks based on total marks
    c.execute('''SELECT m.learner_admission, SUM(m.marks) as total_marks 
                 FROM marks m 
                 JOIN learners l ON m.learner_admission = l.admission_no 
                 WHERE l.grade=? AND m.exam_type=? AND m.term=? AND m.year=? 
                 GROUP BY m.learner_admission''',
              (grade, exam_type, term, year))
    totals = c.fetchall()
    sorted_totals = sorted(totals, key=lambda x: x['total_marks'] or 0, reverse=True)
    rank_dict = {adm_no: i + 1 for i, (adm_no, _) in enumerate(sorted_totals)}
    total_students = len(learners)
    logging.debug(f"Calculated ranks for {total_students} students")
    
    # Create temporary directory for PDFs
    with tempfile.TemporaryDirectory() as tmpdir:
        # Watermark
        watermark = Image.new('RGBA', (200, 100), (255, 255, 255, 0))
        draw = ImageDraw.Draw(watermark)
        try:
            font = ImageFont.truetype("arial.ttf", 20)
        except:
            font = ImageFont.load_default()
        draw.text((10, 40), "Jonyo Junior Secondary", fill=(0, 0, 0, 128), font=font)
        watermark_path = os.path.join(tmpdir, 'watermark.png')
        watermark.save(watermark_path)
        
        def add_watermark(canvas, doc):
            canvas.saveState()
            canvas.setFillAlpha(0.2)
            canvas.drawImage(watermark_path, 200, 400, width=200, height=100)
            canvas.restoreState()
        
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
            for learner in learners:
                adm_no, full_name = learner
                logging.debug(f"Generating report card for learner: {adm_no}")
                
                # Fetch main marks (consistent with /download_pdf and /manage_marks)
                c.execute('''SELECT m.learning_area_id, m.marks, pl.points, pl.level, pl.comment 
                             FROM marks m 
                             JOIN learners l ON m.learner_admission = l.admission_no 
                             JOIN performance_levels pl ON m.marks BETWEEN pl.min_mark AND pl.max_mark 
                             WHERE m.learner_admission=? AND m.exam_type=? AND m.term=? AND m.year=? AND m.grade=?''',
                          (adm_no, exam_type, term, year, grade))
                marks_data = c.fetchall()
                marks = {row['learning_area_id']: (row['marks'], row['points'] or 0, row['level'] or 'N/A', row['comment'] or 'N/A') for row in marks_data}
                logging.debug(f"Fetched marks for {adm_no}: {len(marks_data)} entries")
                
                # Fetch CAT marks for End Term (consistent with /download_pdf)
                cat_marks = {}
                if exam_type == 'End Term':
                    c.execute('''SELECT m.learning_area_id, m.marks 
                                 FROM marks m 
                                 WHERE m.learner_admission=? AND m.exam_type='CAT' AND m.term=? AND m.year=? AND m.grade=?''',
                              (adm_no, term, year, grade))
                    cat_marks = {row['learning_area_id']: row['marks'] for row in c.fetchall()}
                    logging.debug(f"Fetched CAT marks for {adm_no}: {len(cat_marks)} entries")
                
                # Skip if no marks are found for this learner
                if not marks_data:
                    logging.warning(f"No marks found for learner {adm_no}, skipping report card")
                    continue
                
                # Calculate total marks and grade
                total_marks = sum(row['marks'] for row in marks_data) if marks_data else 0
                total_grade = 'N/A'
                total_comment = 'N/A'
                for min_marks, max_marks, grade_level, comment in total_performance_levels:
                    if min_marks <= total_marks <= max_marks:
                        total_grade = grade_level
                        total_comment = comment
                        break
                
                # Calculate total points
                total_points = sum(row['points'] or 0 for row in marks_data) if marks_data else 0
                
                # Fetch fees
                c.execute("SELECT total_fee, balance FROM fees WHERE learner_admission=? AND term=? AND year=?",
                          (adm_no, term, year))
                fee_data = c.fetchone()
                total_fee = fee_data['total_fee'] if fee_data else 0
                balance = fee_data['balance'] if fee_data else 0
                
                # Create PDF
                pdf_buffer = io.BytesIO()
                doc = SimpleDocTemplate(pdf_buffer, pagesize=A4, topMargin=0.5*inch, bottomMargin=0.5*inch)
                elements = []
                styles = getSampleStyleSheet()
                centered_style = ParagraphStyle(name='Centered', parent=styles['Title'], alignment=TA_CENTER, spaceAfter=12)
                normal_centered = ParagraphStyle(name='NormalCentered', parent=styles['Normal'], alignment=TA_CENTER, spaceAfter=6)
                
                # Header
                elements.append(Paragraph("Jonyo Junior Secondary School", centered_style))
                elements.append(Paragraph("Report Card", centered_style))
                elements.append(Paragraph(f"Name: {full_name}", normal_centered))
                elements.append(Paragraph(f"Admission No: {adm_no}", normal_centered))
                elements.append(Paragraph(f"Grade: {grade} | Term: {term} | Year: {year} | Exam: {exam_type}", normal_centered))
                elements.append(Paragraph(f"Generated on: {datetime.now(pytz.timezone('Africa/Nairobi')).strftime('%Y-%m-%d %I:%M %p %Z')}", normal_centered))
                elements.append(Spacer(1, 0.2*inch))
                
                # Marks table (consistent with /download_pdf)
                headers = ['Learning Areas', 'Marks', 'Performance Levels', 'Points', 'Comment', 'Teacher']
                if exam_type == 'End Term':
                    headers.insert(1, 'CAT Marks')
                
                table_data = [headers]
                for area_id, area_name in zip(area_ids, area_names):
                    if area_id not in marks:
                        row = [area_name, 'Not Recorded', 'N/A', 'N/A', 'Marks not submitted', teacher_assignments.get(area_id, 'Not Assigned')]
                        if exam_type == 'End Term':
                            row.insert(1, 'N/A')
                        table_data.append(row)
                        continue
                    mark, points, level, comment = marks.get(area_id, (0, 0, 'N/A', 'N/A'))
                    teacher_name = teacher_assignments.get(area_id, 'Not Assigned')
                    row = [area_name, str(mark) if mark else '0', level, str(points) if points else '0', comment, teacher_name]
                    if exam_type == 'End Term':
                        cat_mark = cat_marks.get(area_id, 'N/A')
                        row.insert(1, str(cat_mark))
                    table_data.append(row)
                
                col_widths = [1.5*inch, 0.8*inch, 1.0*inch, 0.8*inch, 1.5*inch, 1.2*inch]
                if exam_type == 'End Term':
                    col_widths.insert(1, 0.8*inch)
                
                table = Table(table_data, colWidths=col_widths)
                table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 10),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black),
                    ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ]))
                elements.append(table)
                elements.append(Spacer(1, 0.2*inch))
                
                # Footer
                rank = rank_dict.get(adm_no, 'N/A')
                elements.append(Paragraph(f"Total Marks: {total_marks}", styles['Normal']))
                elements.append(Paragraph(f"Grade: {total_grade} ({total_comment})", styles['Normal']))
                elements.append(Paragraph(f"Points: {total_points}", styles['Normal']))
                elements.append(Paragraph(f"Rank: {rank} out of {total_students}", styles['Normal']))
                elements.append(Paragraph(f"Total Fee: {total_fee}", styles['Normal']))
                elements.append(Paragraph(f"Balance: {balance}", styles['Normal']))
                elements.append(Paragraph("Class Teacher Comment: Keep up the good work.", styles['Normal']))
                elements.append(Paragraph(f"Principal Comment: Continue to strive for excellence. - {principal_name}", styles['Normal']))
                elements.append(Paragraph(f"Class Teacher Signature: Signed: {class_teacher}", styles['Normal']))
                elements.append(Paragraph(f"Principal Signature: Signed: {principal_name}", styles['Normal']))
                elements.append(Spacer(1, 0.2*inch))
                elements.append(Paragraph("School Stamp:", styles['Normal']))
                stamp_table = Table([['']], colWidths=[1*inch], rowHeights=[0.5*inch])
                stamp_table.setStyle(TableStyle([('GRID', (0, 0), (-1, -1), 1, colors.black)]))
                elements.append(stamp_table)
                
                # Build PDF
                doc.build(elements, onFirstPage=add_watermark, onLaterPages=add_watermark)
                pdf_buffer.seek(0)
                
                # Add to ZIP
                pdf_name = f"report_card_{adm_no}_{term}_{year}_{exam_type}.pdf".replace(' ', '_')
                zip_file.writestr(pdf_name, pdf_buffer.getvalue())
        
        conn.close()
        zip_buffer.seek(0)
        
        filename = f"report_cards_{grade.lower().replace(' ', '_')}_{exam_type.lower().replace(' ', '_')}_{term.lower().replace(' ', '_')}_{year}.zip"
        logging.info(f"Report cards ZIP downloaded for grade={grade}, term={term}, year={year}, exam_type={exam_type} by user_id={session.get('user_id')}")
        return send_file(zip_buffer, as_attachment=True, download_name=filename, mimetype='application/zip')
    
    
@app.route('/download_pdf/<admission_no>/<term>/<year>/<exam_type>')
@login_required
def download_pdf(admission_no, term, year, exam_type):
    logging.debug(f"Generating PDF for admission_no={admission_no}, term={term}, year={year}, exam_type={exam_type}")
    
    if 'role' not in session or session['role'] not in ['learner', 'parent']:
        flash('Unauthorized access.', 'danger')
        logging.warning(f"Unauthorized access to download_pdf: user_id={session.get('user_id', 'unknown')}, role={session.get('role', 'unknown')}")
        return redirect(url_for(session['role'] + '_dashboard'))
    
    conn = sqlite3.connect('jonyo_school.db')
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    
    # Fetch learner details
    c.execute("SELECT full_name, grade, photo_path FROM learners WHERE admission_no=?", (admission_no,))
    learner = c.fetchone()
    if not learner:
        conn.close()
        flash('Learner not found.', 'danger')
        logging.error(f"Learner not found: admission_no={admission_no}")
        return redirect(url_for(session['role'] + '_dashboard'))
    
    full_name, grade, photo_path = learner
    logging.debug(f"Learner found: {full_name}, grade={grade}")
    
    # Normalize term and exam_type
    term = term.lower().strip().title().replace('Term1', 'Term 1').replace('Term2', 'Term 2').replace('Term3', 'Term 3')
    exam_type = exam_type.lower().strip().replace('-', ' ').title().replace('Midterm', 'Mid Term').replace('Endterm', 'End Term')
    
    # Validate inputs
    valid_exam_types = ['Mid Term', 'End Term', 'CAT']
    valid_terms = ['Term 1', 'Term 2', 'Term 3']
    if exam_type not in valid_exam_types or term not in valid_terms:
        conn.close()
        flash('Invalid exam type or term.', 'danger')
        logging.error(f"Invalid exam type or term: exam_type={exam_type}, term={term}")
        return redirect(url_for(session['role'] + '_dashboard'))
    
    try:
        year = int(year)
        if year < 2000 or year > datetime.now().year + 1:
            raise ValueError
    except ValueError:
        conn.close()
        flash('Invalid year.', 'danger')
        logging.error(f"Invalid year: year={year}")
        return redirect(url_for(session['role'] + '_dashboard'))
    
    # Fetch learning areas
    c.execute("SELECT id, name FROM learning_areas WHERE grade=?", (grade,))
    learning_areas = c.fetchall()
    if not learning_areas:
        conn.close()
        flash('No learning areas found for this grade.', 'danger')
        logging.error(f"No learning areas found for grade={grade}")
        return redirect(url_for(session['role'] + '_dashboard'))
    area_ids = [area['id'] for area in learning_areas]
    area_names = [area['name'] for area in learning_areas]
    logging.debug(f"Fetched {len(area_names)} learning areas for grade {grade}")
    
    # Fetch performance levels
    c.execute("SELECT min_mark, max_mark, level, points, comment FROM performance_levels")
    performance_levels = c.fetchall()
    if not performance_levels:
        conn.close()
        flash('Performance levels not configured.', 'danger')
        logging.error("Performance levels not found in database")
        return redirect(url_for(session['role'] + '_dashboard'))
    
    # Fetch total marks performance levels
    c.execute("SELECT min_total_marks, max_total_marks, grade, comment FROM total_marks_performance_levels")
    total_performance_levels = c.fetchall()
    if not total_performance_levels:
        conn.close()
        flash('Total marks performance levels not configured.', 'danger')
        logging.error("Total marks performance levels not found in database")
        return redirect(url_for(session['role'] + '_dashboard'))
    
    # Fetch teacher assignments
    c.execute("SELECT learning_area_id, u.full_name FROM teacher_assignments ta JOIN users u ON ta.teacher_id = u.id")
    teacher_assignments = dict(c.fetchall())
    logging.debug(f"Fetched teacher assignments: {len(teacher_assignments)} entries")
    
    # Fetch marks (uploaded by admins or teachers via manage_marks)
    c.execute('''SELECT m.learning_area_id, m.marks, pl.points, pl.level, pl.comment 
                 FROM marks m 
                 JOIN learners l ON m.learner_admission = l.admission_no 
                 JOIN performance_levels pl ON m.marks BETWEEN pl.min_mark AND pl.max_mark 
                 WHERE m.learner_admission=? AND m.exam_type=? AND m.term=? AND m.year=? AND m.grade=?''',
              (admission_no, exam_type, term, year, grade))
    marks_data = c.fetchall()
    marks = {row['learning_area_id']: (row['marks'] or 0, row['points'] or 0, row['level'] or 'N/A', row['comment'] or 'N/A') for row in marks_data}
    if not marks_data:
        conn.close()
        flash('No marks found for this learner for the specified term, year, and exam type.', 'warning')
        logging.warning(f"No marks found: admission_no={admission_no}, exam_type={exam_type}, term={term}, year={year}")
        return redirect(url_for(session['role'] + '_dashboard'))
    logging.debug(f"Fetched marks: {len(marks_data)} entries")
    
    # Fetch CAT marks for End Term (consistent with manage_marks logic)
    cat_marks = {}
    if exam_type == 'End Term':
        c.execute('''SELECT m.learning_area_id, m.marks 
                     FROM marks m 
                     WHERE m.learner_admission=? AND m.exam_type='CAT' AND m.term=? AND m.year=? AND m.grade=?''',
                  (admission_no, term, year, grade))
        cat_marks = {row['learning_area_id']: row['marks'] for row in c.fetchall()}
        logging.debug(f"Fetched CAT marks: {len(cat_marks)} entries")
    
    # Calculate total marks and grade
    total_marks = sum(row['marks'] for row in marks_data) if marks_data else 0
    total_grade = 'N/A'
    total_comment = 'N/A'
    for min_marks, max_marks, grade_level, comment in total_performance_levels:
        if min_marks <= total_marks <= max_marks:
            total_grade = grade_level
            total_comment = comment
            break
    logging.debug(f"Calculated total_marks={total_marks}, total_grade={total_grade}")
    
    # Calculate total points
    total_points = sum(row['points'] or 0 for row in marks_data) if marks_data else 0
    
    # Fetch fees
    c.execute("SELECT total_fee, balance FROM fees WHERE learner_admission=? AND term=? AND year=?",
              (admission_no, term, year))
    fee_data = c.fetchone()
    total_fee = fee_data['total_fee'] if fee_data else 0
    balance = fee_data['balance'] if fee_data else 0
    logging.debug(f"Fetched fees: total_fee={total_fee}, balance={balance}")
    
    # Fetch total learners and calculate rank based on total marks
    c.execute("SELECT COUNT(*) FROM learners WHERE grade=?", (grade,))
    total_learners = c.fetchone()[0]
    c.execute('''SELECT m.learner_admission, SUM(m.marks) as total_marks 
                 FROM marks m 
                 JOIN learners l ON m.learner_admission = l.admission_no 
                 WHERE l.grade=? AND m.exam_type=? AND m.term=? AND m.year=? 
                 GROUP BY m.learner_admission''',
              (grade, exam_type, term, year))
    totals = c.fetchall()
    sorted_totals = sorted(totals, key=lambda x: x['total_marks'] or 0, reverse=True)
    rank_dict = {adm_no: i + 1 for i, (adm_no, _) in enumerate(sorted_totals)}
    rank = rank_dict.get(admission_no, 'N/A')
    logging.debug(f"Calculated rank={rank} out of {total_learners}")
    
    # Fetch class teacher
    c.execute("SELECT u.full_name FROM class_teachers ct JOIN users u ON ct.teacher_id=u.id WHERE ct.grade=?", (grade,))
    class_teacher_result = c.fetchone()
    class_teacher_name = class_teacher_result['full_name'] if class_teacher_result else 'Not Assigned'
    
    # Fetch principal
    c.execute("SELECT principal_name FROM term_info WHERE term=? AND start_date LIKE ?", (term, f'{year}%'))
    principal_result = c.fetchone()
    principal_name = principal_result['principal_name'] if principal_result else 'Not Set'
    
    # Create temporary directory for watermark
    with tempfile.TemporaryDirectory() as tmpdir:
        # Watermark
        watermark = Image.new('RGBA', (200, 100), (255, 255, 255, 0))
        draw = ImageDraw.Draw(watermark)
        try:
            font = ImageFont.truetype("arial.ttf", 20)
        except:
            font = ImageFont.load_default()
        draw.text((10, 40), "Jonyo Junior Secondary", fill=(0, 0, 0, 128), font=font)
        watermark_path = os.path.join(tmpdir, 'watermark.png')
        watermark.save(watermark_path)
        
        def add_watermark(canvas, doc):
            canvas.saveState()
            canvas.setFillAlpha(0.2)
            canvas.drawImage(watermark_path, 200, 400, width=200, height=100)
            canvas.restoreState()
        
        # Create PDF
        output = io.BytesIO()
        doc = SimpleDocTemplate(output, pagesize=A4, topMargin=0.5*inch, bottomMargin=0.5*inch)
        elements = []
        styles = getSampleStyleSheet()
        centered_style = ParagraphStyle(name='Centered', parent=styles['Title'], alignment=TA_CENTER, spaceAfter=12)
        normal_centered = ParagraphStyle(name='NormalCentered', parent=styles['Normal'], alignment=TA_CENTER, spaceAfter=6)
        
        # Header
        elements.append(Paragraph("Jonyo Junior Secondary School", centered_style))
        elements.append(Paragraph("Report Card", centered_style))
        elements.append(Paragraph(f"Name: {full_name}", normal_centered))
        elements.append(Paragraph(f"Admission No: {admission_no}", normal_centered))
        elements.append(Paragraph(f"Grade: {grade} | Term: {term} | Year: {year} | Exam: {exam_type}", normal_centered))
        elements.append(Paragraph(f"Generated on: {datetime.now(pytz.timezone('Africa/Nairobi')).strftime('%Y-%m-%d %I:%M %p %Z')}", normal_centered))
        elements.append(Spacer(1, 0.2*inch))
        
        # Marks table
        headers = ['Learning Areas', 'Marks', 'Performance Levels', 'Points', 'Comment', 'Teacher']
        if exam_type == 'End Term':
            headers.insert(1, 'CAT Marks')
        
        table_data = [headers]
        for area_id, area_name in zip(area_ids, area_names):
            if area_id not in marks:
                row = [area_name, 'Not Recorded', 'N/A', 'N/A', 'Marks not submitted', teacher_assignments.get(area_id, 'Not Assigned')]
                if exam_type == 'End Term':
                    row.insert(1, 'N/A')
                table_data.append(row)
                continue
            mark, points, level, comment = marks.get(area_id, (0, 0, 'N/A', 'N/A'))
            teacher_name = teacher_assignments.get(area_id, 'Not Assigned')
            row = [area_name, str(mark) if mark else '0', level, str(points) if points else '0', comment, teacher_name]
            if exam_type == 'End Term':
                cat_mark = cat_marks.get(area_id, 'N/A')
                row.insert(1, str(cat_mark))
            table_data.append(row)
        
        col_widths = [1.5*inch, 0.8*inch, 1.0*inch, 0.8*inch, 1.5*inch, 1.2*inch]
        if exam_type == 'End Term':
            col_widths.insert(1, 0.8*inch)
        
        table = Table(table_data, colWidths=col_widths)
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        elements.append(table)
        elements.append(Spacer(1, 0.2*inch))
        
        # Footer
        elements.append(Paragraph(f"Total Marks: {total_marks}", styles['Normal']))
        elements.append(Paragraph(f"Grade: {total_grade} ({total_comment})", styles['Normal']))
        elements.append(Paragraph(f"Points: {total_points}", styles['Normal']))
        elements.append(Paragraph(f"Rank: {rank} out of {total_learners}", styles['Normal']))
        elements.append(Paragraph(f"Total Fee: {total_fee}", styles['Normal']))
        elements.append(Paragraph(f"Balance: {balance}", styles['Normal']))
        elements.append(Paragraph("Class Teacher Comment: Keep up the good work.", styles['Normal']))
        elements.append(Paragraph(f"Principal Comment: Continue to strive for excellence. - {principal_name}", styles['Normal']))
        elements.append(Paragraph(f"Class Teacher Signature: Signed: {class_teacher_name}", styles['Normal']))
        elements.append(Paragraph(f"Principal Signature: Signed: {principal_name}", styles['Normal']))
        elements.append(Spacer(1, 0.2*inch))
        elements.append(Paragraph("School Stamp: ____________________", styles['Normal']))
        
        # Build PDF
        doc.build(elements, onFirstPage=add_watermark, onLaterPages=add_watermark)
        output.seek(0)
    
    conn.close()
    logging.debug("PDF generated successfully")
    
    filename = f"report_card_{admission_no}_{term}_{year}_{exam_type}.pdf".replace(' ', '_')
    return send_file(output, download_name=filename, as_attachment=True)

@app.route('/edit_term', methods=['GET', 'POST'])
def edit_term():
    if 'role' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))
    conn = sqlite3.connect('jonyo_school.db')
    c = conn.cursor()
    if request.method == 'POST':
        term = request.form['term']
        start_date = request.form['start_date']
        end_date = request.form['end_date']
        principal_name = request.form['principal_name']
        c.execute("INSERT INTO term_info (term, start_date, end_date, principal_name) VALUES (?, ?, ?, ?)",
                  (term, start_date, end_date, principal_name))
        conn.commit()
        flash('Term information updated.', 'success')
    c.execute("SELECT term, start_date, end_date, principal_name FROM term_info ORDER BY id DESC")
    term_info = c.fetchall()
    conn.close()
    return render_template('edit_term.html', term_info=term_info)

@app.route('/edit_home', methods=['GET', 'POST'])
def edit_home():
    if 'role' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))
    conn = sqlite3.connect('jonyo_school.db')
    c = conn.cursor()
    if request.method == 'POST':
        about = request.form['about']
        contact = request.form['contact']
        announcement = request.form['announcement']
        c.execute("INSERT OR REPLACE INTO school_info (id, about, contact, announcement) VALUES (1, ?, ?, ?)",
                  (about, contact, announcement))
        conn.commit()
        flash('Home page updated.', 'success')
    c.execute("SELECT about, contact, announcement FROM school_info WHERE id=1")
    info = c.fetchone()
    conn.close()
    return render_template('edit_home.html', about=info[0] if info else '', contact=info[1] if info else '', announcement=info[2] if info else '')


@app.route('/download_results', methods=['GET', 'POST'])
@login_required
def download_results():
    if session.get('role') not in ['admin']:
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('login'))
    
    form = ResultsExcelForm()
    conn = sqlite3.connect('jonyo_school.db')
    c = conn.cursor()
    
    # Populate term choices
    try:
        c.execute("SELECT DISTINCT term FROM marks ORDER BY term")
        terms = c.fetchall()
        form.term.choices = [(t[0], t[0]) for t in terms] if terms else [('Term 1', 'Term 1')]
        logging.debug(f"Populated term choices: {form.term.choices}")
    except sqlite3.Error as e:
        flash(f'Database error fetching terms: {str(e)}.', 'danger')
        logging.error(f"Database error fetching terms: {str(e)}")
        conn.close()
        return render_template('download_results.html', form=form)
    
    # Handle GET with query parameters or POST with form
    if request.method == 'POST' and form.validate_on_submit():
        grade = form.grade.data
        term = form.term.data
        year = form.year.data
        exam_type = form.exam_type.data
    else:
        grade = request.args.get('grade')
        term = request.args.get('term')
        year = request.args.get('year')
        exam_type = request.args.get('exam_type')
        
        # If any parameters are missing, render the form instead of redirecting with error
        if not all([grade, term, year, exam_type]):
            logging.debug("Missing query parameters in GET request, rendering form")
            conn.close()
            return render_template('download_results.html', form=form)
        
        # Validate query parameters
        valid_grades = ['Grade 7', 'Grade 8', 'Grade 9']
        valid_exam_types = ['Mid Term', 'End Term', 'CAT']
        try:
            year = int(year)
            if grade not in valid_grades or exam_type not in valid_exam_types or year < 2000 or year > datetime.now().year + 1:
                raise ValueError
        except ValueError:
            flash('Invalid parameters provided.', 'danger')
            logging.warning(f"Invalid parameters: grade={grade}, term={term}, year={year}, exam_type={exam_type}")
            conn.close()
            return render_template('download_results.html', form=form)
    
    try:
        # Fetch learning areas
        c.execute("SELECT id, name FROM learning_areas WHERE grade=? ORDER BY name", (grade,))
        learning_areas = c.fetchall()
        if not learning_areas:
            flash(f'No learning areas found for {grade}.', 'warning')
            logging.warning(f"No learning areas found for grade={grade}")
            conn.close()
            return redirect(url_for('admin_dashboard' if session['role'] == 'admin' else 'teacher_dashboard'))
        logging.debug(f"Fetched {len(learning_areas)} learning areas for grade {grade}")
        
        # Fetch learners
        c.execute("SELECT admission_no, full_name FROM learners WHERE grade=? ORDER BY full_name", (grade,))
        learners = c.fetchall()
        if not learners:
            flash(f'No learners found in {grade}.', 'warning')
            logging.warning(f"No learners found in grade={grade}")
            conn.close()
            return redirect(url_for('admin_dashboard' if session['role'] == 'admin' else 'teacher_dashboard'))
        logging.debug(f"Fetched {len(learners)} learners for grade {grade}")
        
        # Fetch marks
        c.execute("""
            SELECT m.learner_admission, la.name, m.marks, m.points
            FROM marks m
            JOIN learning_areas la ON m.learning_area_id=la.id
            WHERE m.grade=? AND m.term=? AND m.year=? AND m.exam_type=?
        """, (grade, term, year, exam_type))
        marks = c.fetchall()
        logging.debug(f"Fetched {len(marks)} marks entries for grade={grade}, term={term}, year={year}, exam_type={exam_type}")
        
        # If no marks are found, notify the user but still generate an empty Excel file
        if not marks:
            flash(f'No marks found for {grade}, {term}, {year}, {exam_type}. Generating empty results sheet.', 'warning')
            logging.warning(f"No marks found for grade={grade}, term={term}, year={year}, exam_type={exam_type}")
        
        # Create DataFrame
        data = {
            'Admission No': {learner[0]: learner[0] for learner in learners},
            'Full Name': {learner[0]: learner[1] for learner in learners}
        }
        for la in learning_areas:
            data[la[1]] = {learner[0]: '-' for learner in learners}
        data['Total Marks'] = {learner[0]: 0 for learner in learners}
        data['Performance Level'] = {learner[0]: 'N/A' for learner in learners}
        data['Comment'] = {learner[0]: 'No performance level' for learner in learners}
        
        # Populate marks and calculate total marks
        for mark in marks:
            admission_no, la_name, mark_value, points = mark
            data[la_name][admission_no] = f"{mark_value} ({points})"
            data['Total Marks'][admission_no] += mark_value
        
        # Fetch performance levels
        for admission_no in data['Total Marks']:
            total_marks = data['Total Marks'][admission_no]
            c.execute("SELECT grade, comment FROM total_marks_performance_levels WHERE ? BETWEEN min_total_marks AND max_total_marks",
                     (total_marks,))
            performance = c.fetchone()
            if performance:
                data['Performance Level'][admission_no] = performance[0]
                data['Comment'][admission_no] = performance[1]
        
        # Create DataFrame
        columns = ['Admission No', 'Full Name'] + [la[1] for la in learning_areas] + ['Total Marks', 'Performance Level', 'Comment']
        df = pd.DataFrame(data, columns=columns)
        df = df.sort_values('Full Name')
        logging.debug(f"Created DataFrame with {len(df)} rows and {len(columns)} columns")
        
        # Export to Excel
        output = io.BytesIO()
        with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
            df.to_excel(writer, sheet_name=f'{grade}_{term}_{year}', index=False)
            worksheet = writer.sheets[f'{grade}_{term}_{year}']
            worksheet.set_column(0, 0, 15)  # Admission No
            worksheet.set_column(1, 1, 25)  # Full Name
            for i, _ in enumerate(learning_areas, 2):
                worksheet.set_column(i, i, 15)  # Learning areas
            worksheet.set_column(len(learning_areas) + 2, len(learning_areas) + 2, 15)  # Total Marks
            worksheet.set_column(len(learning_areas) + 3, len(learning_areas) + 3, 20)  # Performance Level
            worksheet.set_column(len(learning_areas) + 4, len(learning_areas) + 4, 30)  # Comment
        
        output.seek(0)
        
        logging.info(f"Results Excel downloaded for grade={grade}, term={term}, year={year}, exam_type={exam_type} by user_id={session.get('user_id')}")
        
        conn.close()
        return send_file(output, as_attachment=True, download_name=f"results_{grade}_{term}_{year}.xlsx", mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
    
    except sqlite3.Error as e:
        flash(f'Database error: {str(e)}.', 'danger')
        logging.error(f"Database error: {str(e)}")
    except Exception as e:
        flash(f'Error generating results Excel: {str(e)}.', 'danger')
        logging.error(f"Error generating Excel: {str(e)}")
    
    conn.close()
    return render_template('download_results.html', form=form)

@app.route('/send_message', methods=['POST'])
def send_message():
    if 'role' not in session or session['role'] not in ['admin', 'teacher', 'bursar']:
        return redirect(url_for('login'))
    message_text = request.form['message']
    conn = sqlite3.connect('jonyo_school.db')
    c = conn.cursor()
    c.execute("INSERT INTO messages (sender_id, message_text, sent_at) VALUES (?, ?, ?)",
              (session['user_id'], message_text, datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
    conn.commit()
    conn.close()
    flash('Message sent to parents.', 'success')
    return redirect(url_for(session['role'] + '_dashboard'))

@app.route('/admin_notes', methods=['GET', 'POST'])
@login_required
def admin_notes():
    if current_user.role != 'admin':
        flash('Unauthorized access.', 'danger')
        logging.warning(f"Unauthorized admin_notes access: user_id={current_user.id}, role={current_user.role}")
        return redirect(url_for('login'))
    
    form = AdminNoteForm()
    
    try:
        with sqlite3.connect('jonyo_school.db') as conn:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            
            if form.validate_on_submit():
                note_text = form.note_text.data
                try:
                    c.execute("INSERT INTO admin_notes (admin_id, note_text, created_at) VALUES (?, ?, ?)",
                              (current_user.id, note_text, datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
                    conn.commit()
                    flash('Note saved successfully.', 'success')
                    logging.info(f"Note created: user_id={current_user.id}, note_text={note_text[:50]}...")
                    return redirect(url_for('admin_notes'))
                except sqlite3.Error as e:
                    flash(f'Error saving note: {str(e)}', 'danger')  # Fixed syntax error
                    logging.error(f"Error saving note: {str(e)}, user_id={current_user.id}")
            
            try:
                c.execute("SELECT id, note_text, created_at FROM admin_notes WHERE admin_id=?", (current_user.id,))
                notes = c.fetchall()
            except sqlite3.Error as e:
                flash(f'Error fetching notes: {str(e)}', 'danger')
                logging.error(f"Error fetching notes: {str(e)}, user_id={current_user.id}")
                notes = []
    
    except sqlite3.Error as e:
        flash(f'Database connection error: {str(e)}', 'danger')
        logging.error(f"Database connection error in admin_notes: {str(e)}, user_id={current_user.id}")
        notes = []
    
    return render_template('admin_notes.html', form=form, notes=notes)

@app.route('/teacher_dashboard', methods=['GET', 'POST'])
@login_required
def teacher_dashboard():
    if current_user.role != 'teacher':
        flash('Unauthorized access.', 'danger')
        logging.warning(f"Unauthorized teacher_dashboard access: user_id={current_user.id}")
        return redirect(url_for('login'))
    
    marks_form = ManageMarksForm()
    message_form = MessageForm()
    
    try:
        conn = sqlite3.connect('jonyo_school.db')
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        
        # Fetch teacher's assigned learning areas and grades
        c.execute('''SELECT la.id, la.name, la.grade
                     FROM learning_areas la
                     JOIN teacher_assignments ta ON la.id = ta.learning_area_id
                     WHERE ta.teacher_id = ?''', (current_user.id,))
        learning_areas = c.fetchall()
        
        # Populate learning_area choices for marks_form
        marks_form.learning_area.choices = [(la['id'], f"{la['grade']} - {la['name']}") for la in learning_areas]
        
        # Fetch learners in teacher's grades
        grades = list(set(la['grade'] for la in learning_areas))
        c.execute('''SELECT admission_no, full_name
                     FROM learners
                     WHERE grade IN ({})'''.format(','.join('?' * len(grades))),
                  grades)
        learners = c.fetchall()
        
        # Fetch parents for messaging
        c.execute('''SELECT DISTINCT u.id, u.full_name
                     FROM users u
                     JOIN parent_learner pl ON u.id = pl.parent_id
                     JOIN learners l ON pl.learner_admission = l.admission_no
                     WHERE l.grade IN ({}) AND u.role = 'parent' '''.format(','.join('?' * len(grades))),
                  grades)
        parents = c.fetchall()
        
        # Fetch teacher's submitted marks
        c.execute('''SELECT m.learner_admission, l.full_name, la.name AS learning_area, m.exam_type, m.marks, m.term, m.year
                     FROM marks m
                     JOIN learners l ON m.learner_admission = l.admission_no
                     JOIN learning_areas la ON m.learning_area_id = la.id
                     WHERE m.teacher_id = ?
                     ORDER BY m.year DESC, m.term, l.full_name''', (current_user.id,))
        submitted_marks = c.fetchall()
        
        # Fetch messages (sent and received)
        c.execute('''SELECT m.message, m.timestamp, u.full_name AS sender_name
                     FROM messages m
                     JOIN users u ON m.sender_id = u.id
                     WHERE m.receiver_id = ? OR m.sender_id = ?
                     ORDER BY m.timestamp DESC LIMIT 10''', (current_user.id, current_user.id))
        messages = c.fetchall()
        
        if request.method == 'POST':
            if marks_form.validate_on_submit() and 'submit_marks' in request.form:
                try:
                    c.execute('''SELECT admission_no FROM learners WHERE admission_no = ?''', (marks_form.learner_id.data,))
                    if not c.fetchone():
                        flash('Invalid learner admission number.', 'danger')
                    else:
                        c.execute('''SELECT id FROM learning_areas WHERE id = ?''', (marks_form.learning_area.data,))
                        if not c.fetchone():
                            flash('Invalid learning area.', 'danger')
                        else:
                            c.execute('''INSERT INTO marks (learner_admission, learning_area_id, exam_type, marks, term, year, teacher_id)
                                         VALUES (?, ?, ?, ?, ?, ?, ?)''',
                                      (marks_form.learner_id.data, marks_form.learning_area.data, marks_form.exam_type.data,
                                       marks_form.marks.data, marks_form.term.data, marks_form.year.data, current_user.id))
                            conn.commit()
                            flash('Marks submitted successfully.', 'success')
                            logging.info(f"Marks submitted by teacher_id={current_user.id} for learner_admission={marks_form.learner_id.data}")
                            return redirect(url_for('teacher_dashboard'))
                except sqlite3.Error as e:
                    conn.rollback()
                    flash(f'Database error submitting marks: {str(e)}', 'danger')
                    logging.error(f"Database error submitting marks: {str(e)}, teacher_id={current_user.id}")
            
            elif 'submit_message' in request.form:
                return redirect(url_for('send_message'))
        
        conn.close()
        return render_template('teacher_dashboard.html',
                              marks_form=marks_form,
                              message_form=message_form,
                              learning_areas=learning_areas,
                              learners=learners,
                              parents=parents,
                              submitted_marks=submitted_marks,
                              messages=messages,
                              current_year=datetime.now().year)
    
    except sqlite3.Error as e:
        flash(f'Database connection error: {str(e)}', 'danger')
        logging.error(f"Database connection error in teacher_dashboard: {str(e)}")
        return redirect(url_for('login'))
    
@app.route('/delete_note/<int:note_id>', methods=['GET'], endpoint='delete_note_unique')
@login_required
def delete_note(note_id):
    if current_user.role != 'admin':
        flash('Unauthorized access.', 'danger')
        logging.warning(f"Unauthorized delete_note access: note_id={note_id}, user_id={current_user.id}, role={current_user.role}")
        return redirect(url_for('login'))
    
    provided_token = request.args.get('token', '')
    expected_token = hashlib.md5(f"{current_user.id}{app.config['SECRET_KEY']}{int(time.time())//3600}".encode()).hexdigest()
    if provided_token != expected_token:
        flash('Invalid or expired delete token.', 'danger')
        logging.warning(f"Invalid delete token for note_id={note_id}, provided={provided_token}, expected={expected_token}, user_id={current_user.id}")
        return redirect(url_for('admin_notes'))
    
    try:
        with sqlite3.connect('jonyo_school.db') as conn:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            c.execute("SELECT note_text FROM admin_notes WHERE id=? AND admin_id=?", (note_id, current_user.id))
            note = c.fetchone()
            if not note:
                flash('Note not found or unauthorized.', 'danger')
                logging.warning(f"Note not found or unauthorized: note_id={note_id}, user_id={current_user.id}")
                return redirect(url_for('admin_notes'))
            
            c.execute("DELETE FROM admin_notes WHERE id=?", (note_id,))
            conn.commit()
            flash('Note deleted successfully.', 'success')
            logging.info(f"Note deleted: note_id={note_id}, user_id={current_user.id}, note_text={note['note_text'][:50]}...")
    
    except sqlite3.Error as e:
        flash(f'Error deleting note: {str(e)}', 'danger')
        logging.error(f"Error deleting note: note_id={note_id}, {str(e)}, user_id={current_user.id}")
    
    return redirect(url_for('admin_notes'))
    return redirect(url_for('admin_notes'))
@app.route('/learner_dashboard')
@login_required
def learner_dashboard():
    if session.get('role') != 'learner':
        flash('Unauthorized access. Please log in as a learner.', 'danger')
        logging.warning(f"Unauthorized access attempt to learner_dashboard: role={session.get('role')}, session={session}")
        session.clear()
        return redirect(url_for('login'))
    
    user_id = session.get('user_id')
    grade = session.get('grade')
    learner_name = session.get('full_name')
    if not user_id or not grade or not learner_name:
        flash('Session data missing. Please log in again. Contact admin if this persists (rolexoshia@gmail.com).', 'danger')
        logging.error(f"Missing session data: user_id={user_id}, grade={grade}, full_name={learner_name}, session={session}")
        session.clear()
        return redirect(url_for('logout'))
    
    try:
        with sqlite3.connect('jonyo_school.db') as conn:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            
            c.execute("SELECT grade FROM learners WHERE admission_no=?", (user_id,))
            learner = c.fetchone()
            if not learner:
                flash('Learner not found. Contact admin at rolexoshia@gmail.com or 0114745401.', 'danger')
                logging.error(f"Learner not found: admission_no={user_id}, session={session}")
                session.clear()
                return redirect(url_for('logout'))
            if learner['grade'] != grade:
                session['grade'] = learner['grade']
                logging.info(f"Updated session grade for {user_id}: {grade} -> {learner['grade']}")
            
            term_info = None
            c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='term_info'")
            if c.fetchone():
                c.execute("PRAGMA table_info(term_info)")
                columns = [col[1] for col in c.fetchall()]
                if 'is_active' in columns:
                    c.execute("SELECT term, start_date, end_date, principal_name FROM term_info WHERE is_active=1")
                else:
                    c.execute("SELECT term, start_date, end_date, principal_name FROM term_info ORDER BY start_date DESC LIMIT 1")
                term_info = c.fetchone()
            if not term_info:
                term_info = {'term': 'N/A', 'start_date': 'N/A', 'end_date': 'N/A', 'principal_name': 'N/A'}
                flash('No active term information available.', 'warning')
            
            report_cards = []
            c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='marks'")
            if c.fetchone():
                c.execute("""
                    SELECT DISTINCT term, year, exam_type 
                    FROM marks 
                    WHERE learner_admission=? 
                    ORDER BY year DESC, 
                             CASE term 
                                 WHEN 'Term 1' THEN 1 
                                 WHEN 'Term 2' THEN 2 
                                 WHEN 'Term 3' THEN 3 
                             END DESC, 
                             exam_type
                """, (user_id,))
                report_cards = [(row['term'], row['year'], row['exam_type']) for row in c.fetchall()]
                logging.info(f"Report cards for {user_id}: {report_cards}")
            if not report_cards:
                flash('No report cards available.', 'info')
            
            fee_statements = []
            c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='fees'")
            if c.fetchone():
                c.execute("""
                    SELECT total_fee, amount_paid, balance, term, year 
                    FROM fees 
                    WHERE learner_admission=? 
                    ORDER BY year DESC, 
                             CASE term 
                                 WHEN 'Term 1' THEN 1 
                                 WHEN 'Term 2' THEN 2 
                                 WHEN 'Term 3' THEN 3 
                             END DESC
                """, (user_id,))
                fee_statements = [(row['total_fee'], row['amount_paid'], row['balance'], row['term'], row['year']) 
                                 for row in c.fetchall()]
            if not fee_statements:
                flash('No fee statements available.', 'info')
            
            notes = []
            c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='notes'")
            if c.fetchone() and c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='learning_areas'").fetchone():
                c.execute("""
                    SELECT n.id, n.grade, la.name, n.upload_date 
                    FROM notes n 
                    JOIN learning_areas la ON n.learning_area_id=la.id 
                    WHERE n.grade=? 
                    ORDER BY n.upload_date DESC 
                    LIMIT 50
                """, (grade,))
                notes = [(row['id'], row['grade'], row['name'], row['upload_date']) for row in c.fetchall()]
            if not notes:
                flash('No notes available.', 'info')
            
            online_exams = []
            submission_status = {}
            expired_status = {}
            nairobi_tz = pytz.timezone('Africa/Nairobi')
            now = datetime.now(nairobi_tz).strftime('%Y-%m-%d %H:%M:%S')
            logging.info(f"Current time for exams: {now}")
            c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='online_exams'")
            if c.fetchone() and c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='learning_areas'").fetchone():
                c.execute("""
                    SELECT e.id, la.name AS learning_area, e.exam_name, e.start_time, e.end_time 
                    FROM online_exams e 
                    JOIN learning_areas la ON e.learning_area_id=la.id 
                    WHERE e.grade=? AND e.is_active=1
                    ORDER BY e.start_time DESC 
                    LIMIT 50
                """, (grade,))
                online_exams = [(row['id'], row['learning_area'], row['exam_name'], row['start_time'], row['end_time']) 
                               for row in c.fetchall()]
                logging.info(f"Fetched online_exams: {online_exams}")
                for exam in online_exams:
                    exam_id = exam[0]
                    c.execute("SELECT COUNT(*) FROM exam_submissions WHERE exam_id=? AND learner_admission=?", 
                              (exam_id, user_id))
                    submission_status[exam_id] = c.fetchone()['COUNT(*)'] > 0
                    end_time = nairobi_tz.localize(datetime.strptime(exam[4], '%Y-%m-%d %H:%M:%S'))
                    expired_status[exam_id] = end_time < datetime.now(nairobi_tz)
                logging.info(f"Submission status: {submission_status}, Expired status: {expired_status}")
            if not online_exams:
                flash('No online exams available.', 'info')
                logging.warning(f"No online exams found for grade={grade}, user_id={user_id}")
            
            return render_template('learner_dashboard.html',
                                 learner_name=learner_name,
                                 term_info=term_info,
                                 report_cards=report_cards,
                                 fee_statements=fee_statements,
                                 notes=notes,
                                 online_exams=online_exams,
                                 submission_status=submission_status,
                                 expired_status=expired_status,
                                 current_year=datetime.now().year)
    
    except sqlite3.Error as e:
        flash(f'Database error occurred. Contact admin at rolexoshia@gmail.com.', 'danger')
        logging.error(f"Database error in learner_dashboard for {user_id}: {str(e)}, session={session}")
        return render_template('learner_dashboard.html',
                             learner_name=learner_name or 'Unknown',
                             term_info={'term': 'N/A', 'start_date': 'N/A', 'end_date': 'N/A', 'principal_name': 'N/A'},
                             report_cards=[],
                             fee_statements=[],
                             notes=[],
                             online_exams=[],
                             submission_status={},
                             expired_status={},
                             current_year=datetime.now().year)
        
@app.route('/download_note/<int:note_id>')
def download_note(note_id):
    if 'role' not in session or session['role'] != 'learner':
        return redirect(url_for('login'))
    conn = sqlite3.connect('jonyo_school.db')
    c = conn.cursor()
    c.execute("SELECT file_path, downloads FROM notes WHERE id=?", (note_id,))
    note = c.fetchone()
    if note:
        downloads = note[1] + f"{session['user_id']}," if note[1] else f"{session['user_id']},"
        c.execute("UPDATE notes SET downloads=? WHERE id=?", (downloads, note_id))
        conn.commit()
        conn.close()
        return send_file(note[0], as_attachment=True)
    conn.close()
    flash('Note not found.', 'danger')
    return redirect(url_for('learner_dashboard'))

@app.route('/parent_dashboard', methods=['GET', 'POST'])
@login_required
def parent_dashboard():
    if session.get('role') != 'parent':
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('login'))
    
    # Validate session data
    if not session.get('user_id'):
        flash('Session data missing. Please log in again.', 'danger')
        return redirect(url_for('logout'))
    
    conn = sqlite3.connect('jonyo_school.db')
    c = conn.cursor()
    
    # Fetch linked learners with names and grades
    learners = []
    try:
        c.execute("SELECT pl.learner_admission, l.full_name, l.grade FROM parent_learner pl JOIN learners l ON pl.learner_admission=l.admission_no WHERE pl.parent_id=?", 
                 (session['user_id'],))
        learners = c.fetchall()  # Returns [(admission_no, full_name, grade), ...]
    except sqlite3.Error as e:
        flash(f'Database error fetching learners: {str(e)}.', 'danger')
    
    # Get selected learner
    selected_admission = None
    selected_learner = None
    if request.method == 'POST' and request.form.get('learner_admission'):
        selected_admission = request.form['learner_admission']
        # Verify selected learner is linked to parent
        c.execute("SELECT l.admission_no, l.full_name, l.grade FROM learners l JOIN parent_learner pl ON l.admission_no=pl.learner_admission WHERE pl.parent_id=? AND l.admission_no=?", 
                 (session['user_id'], selected_admission))
        selected_learner = c.fetchone()
    elif learners:
        selected_admission = learners[0][0]
        selected_learner = learners[0]
    
    # Fetch term information
    term_info = None
    try:
        c.execute("PRAGMA table_info(term_info)")
        columns = [col[1] for col in c.fetchall()]
        if 'is_active' in columns:
            c.execute("SELECT term, start_date, end_date, principal_name FROM term_info WHERE is_active=1")
        else:
            c.execute("SELECT term, start_date, end_date, principal_name FROM term_info ORDER BY id DESC LIMIT 1")
        term_info = c.fetchone()
    except sqlite3.Error as e:
        flash(f'Database error fetching term info: {str(e)}.', 'danger')
    
    # Fetch report cards, fee statements, notes, and messages
    report_cards = []
    fee_statements = []
    notes = []
    messages = []
    if selected_admission and selected_learner:
        try:
            # Report cards
            c.execute("SELECT DISTINCT year FROM marks WHERE learner_admission=?", (selected_admission,))
            years = [row[0] for row in c.fetchall()]
            if not years:
                years = [datetime.now().year]
            
            for year in years:
                for term in ['Term 1', 'Term 2', 'Term 3']:
                    for exam_type in ['Mid Term', 'End Term', 'CAT']:
                        c.execute("SELECT COUNT(*) FROM marks WHERE learner_admission=? AND term=? AND year=? AND exam_type=?", 
                                 (selected_admission, term, year, exam_type))
                        if c.fetchone()[0] > 0:
                            report_cards.append((term, year, exam_type))
            
            # Fee statements
            c.execute("SELECT total_fee, amount_paid, balance, term, year FROM fees WHERE learner_admission=?", 
                     (selected_admission,))
            fee_statements = c.fetchall()
            
            # Notes (align with learner_dashboard, remove file_path)
            c.execute("SELECT n.id, n.grade, la.name, n.upload_date FROM notes n JOIN learning_areas la ON n.learning_area_id=la.id JOIN learners l ON l.grade=n.grade WHERE l.admission_no=?", 
                     (selected_admission,))
            notes = c.fetchall()
            
            # Messages (filter for parent)
            c.execute("SELECT m.message_text, m.sent_at, u.full_name FROM messages m JOIN users u ON m.sender_id=u.id WHERE m.recipient_id=? ORDER BY m.sent_at DESC", 
                     (session['user_id'],))
            messages = c.fetchall()
        except sqlite3.Error as e:
            flash(f'Database error fetching data: {str(e)}.', 'danger')
    
    conn.close()
    
    if not term_info:
        flash('No active term information available.', 'warning')
    if not learners:
        flash('No learners linked to this parent account.', 'warning')
    
    return render_template('parent_dashboard.html', 
                          learners=learners, 
                          selected_admission=selected_admission, 
                          selected_learner=selected_learner, 
                          term_info=term_info, 
                          report_cards=report_cards, 
                          fee_statements=fee_statements, 
                          notes=notes, 
                          messages=messages,
                          current_year=datetime.now().year)
@app.route('/bursar_dashboard')
@login_required
def bursar_dashboard():
    if session.get('role') != 'bursar':
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('jonyo_school.db')
    c = conn.cursor()
    
    # Fetch term information
    try:
        c.execute("PRAGMA table_info(term_info)")
        columns = [col[1] for col in c.fetchall()]
        if 'is_active' in columns:
            c.execute("SELECT term, start_date, end_date, principal_name FROM term_info WHERE is_active=1")
        else:
            c.execute("SELECT term, start_date, end_date, principal_name FROM term_info ORDER BY id DESC LIMIT 1")
        term_info = c.fetchone()
    except sqlite3.Error as e:
        flash(f'Database error: {str(e)}.', 'danger')
        term_info = None
    finally:
        conn.close()
    
    if not term_info:
        flash('No active term information available.', 'warning')
    
    return render_template('bursar_dashboard.html', term_info=term_info, current_year=datetime.now().year)

@app.route('/timetable')
@login_required
def timetable():
    conn = sqlite3.connect('jonyo_school.db')
    c = conn.cursor()
    
    # Define valid grades
    valid_grades = ['Grade 7', 'Grade 8', 'Grade 9']
    
    # Determine grade based on user role
    if session.get('role') == 'learner':
        grade = session.get('grade')
    else:
        grade = request.args.get('grade', session.get('grade'))
    
    # Validate grade
    if grade and grade not in valid_grades:
        flash('Invalid grade selected.', 'danger')
        grade = None
    
    # Fetch timetable data
    timetable_data = []
    if grade:
        try:
            c.execute("SELECT day, time_slot, learning_area, teacher FROM timetable WHERE grade=?", (grade,))
            timetable_data = c.fetchall()
        except sqlite3.Error as e:
            flash(f'Database error: {str(e)}.', 'danger')
    
    # Fetch available grades
    try:
        c.execute("SELECT DISTINCT grade FROM learners WHERE grade IN (?, ?, ?)", valid_grades)
        grades = [row[0] for row in c.fetchall()]
        print(f"Fetched grades: {grades}")  # Debug
        if not grades:
            grades = valid_grades
            flash('No grades found in learners table. Showing all available grades.', 'warning')
    except sqlite3.Error as e:
        flash(f'Database error fetching grades: {str(e)}.', 'danger')
        grades = valid_grades
    
    conn.close()
    
    # Flash warning if no timetable data
    if not timetable_data and grade:
        flash(f'No timetable data available for {grade}. Please contact the administrator.', 'warning')
    
    return render_template('timetable.html', 
                          timetable_data=timetable_data, 
                          selected_grade=grade, 
                          grades=grades, 
                          current_year=datetime.now().year)
    
@app.route('/download_exam_results/<int:exam_id>')
def download_exam_results(exam_id):
    if 'role' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))
    conn = sqlite3.connect('jonyo_school.db')
    c = conn.cursor()
    c.execute("SELECT ea.learner_admission, l.full_name, ea.answer_text, eq.question_text, ea.submitted_at FROM exam_answers ea JOIN learners l ON ea.learner_admission=l.admission_no JOIN exam_questions eq ON ea.question_id=eq.id WHERE ea.exam_id=?", (exam_id,))
    results = c.fetchall()
    data = {
        'Admission No': [],
        'Full Name': [],
        'Question': [],
        'Answer': [],
        'Submitted At': []
    }
    for result in results:
        data['Admission No'].append(result[0])
        data['Full Name'].append(result[1])
        data['Question'].append(result[3])
        data['Answer'].append(result[2])
        data['Submitted At'].append(result[4])
    df = pd.DataFrame(data)
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
        df.to_excel(writer, index=False, sheet_name='Exam Results')
        workbook = writer.book
        worksheet = writer.sheets['Exam Results']
        worksheet.insert_image('A1', os.path.join('static', 'watermark.png'), {'x_scale': 0.5, 'y_scale': 0.5})
    output.seek(0)
    conn.close()
    return send_file(output, download_name=f"exam_results_{exam_id}.xlsx", as_attachment=True)


@app.route('/assign_class_teacher', methods=['GET', 'POST'])
def assign_class_teacher():
    if 'role' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))
    conn = sqlite3.connect('jonyo_school.db')
    c = conn.cursor()
    
    grades = ['Grade 7', 'Grade 8', 'Grade 9']  # Define available grades
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'assign':
            teacher_id = request.form.get('teacher_id')
            grade = request.form.get('grade')
            if teacher_id and grade:
                # Check if teacher is already assigned to this grade
                c.execute("SELECT COUNT(*) FROM class_teachers WHERE teacher_id = ? AND grade = ?", (teacher_id, grade))
                if c.fetchone()[0] == 0:
                    c.execute("INSERT INTO class_teachers (teacher_id, grade) VALUES (?, ?)", (teacher_id, grade))
                    conn.commit()
                    flash('Class teacher assigned successfully.', 'success')
                else:
                    flash('Teacher is already assigned as class teacher for this grade.', 'danger')
        elif action == 'delete':
            teacher_id = request.form.get('teacher_id')
            grade = request.form.get('grade')
            if teacher_id and grade:
                c.execute("DELETE FROM class_teachers WHERE teacher_id=? AND grade=?", (teacher_id, grade))
                conn.commit()
                flash('Class teacher assignment removed successfully.', 'success')
    
    # Fetch teachers and current class teacher assignments
    c.execute("SELECT id, full_name FROM users WHERE role='teacher'")
    teachers = c.fetchall()
    c.execute("SELECT ct.teacher_id, u.full_name, ct.grade FROM class_teachers ct JOIN users u ON ct.teacher_id = u.id")
    class_teachers = c.fetchall()  # Match the template variable name
    conn.close()
    return render_template('assign_class_teacher.html', grades=grades, teachers=teachers, class_teachers=class_teachers)



@app.route('/assign_teachers', methods=['GET', 'POST'])
def assign_teachers():
    if 'role' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))
    conn = sqlite3.connect('jonyo_school.db')
    c = conn.cursor()
    
    grades = ['Grade 7', 'Grade 8', 'Grade 9']  # Define available grades
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'assign':
            teacher_id = request.form.get('teacher_id')
            grade = request.form.get('grade')
            learning_area_id = request.form.get('learning_area')
            if teacher_id and grade and learning_area_id:
                # Check if assignment already exists
                c.execute("SELECT COUNT(*) FROM teacher_assignments ta "
                          "JOIN learning_areas la ON ta.learning_area_id = la.id "
                          "WHERE ta.teacher_id = ? AND la.grade = ? AND ta.learning_area_id = ?",
                          (teacher_id, grade, learning_area_id))
                if c.fetchone()[0] == 0:
                    c.execute("INSERT INTO teacher_assignments (teacher_id, learning_area_id) VALUES (?, ?)",
                              (teacher_id, learning_area_id))
                    conn.commit()
                    flash('Teacher assigned successfully.', 'success')
                else:
                    flash('Teacher is already assigned to this grade and learning area.', 'danger')
        elif action == 'delete':
            teacher_id = request.form.get('teacher_id')
            learning_area_id = request.form.get('learning_area_id')
            if teacher_id and learning_area_id:
                c.execute("DELETE FROM teacher_assignments WHERE teacher_id=? AND learning_area_id=?",
                          (teacher_id, learning_area_id))
                conn.commit()
                flash('Teacher assignment removed successfully.', 'success')
    
    # Fetch teachers and learning areas
    c.execute("SELECT id, full_name FROM users WHERE role='teacher'")
    teachers = c.fetchall()
    c.execute("SELECT id, name, grade FROM learning_areas")
    learning_areas = c.fetchall()
    c.execute("SELECT ta.teacher_id, u.full_name, la.grade, la.name "
              "FROM teacher_assignments ta "
              "JOIN users u ON ta.teacher_id = u.id "
              "JOIN learning_areas la ON ta.learning_area_id = la.id")
    assignments = c.fetchall()
    conn.close()
    return render_template('assign_teachers.html', grades=grades, teachers=teachers, learning_areas=learning_areas, assignments=assignments)

@app.route('/manage_learning_areas', methods=['GET', 'POST'])
def manage_learning_areas():
    if 'role' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('jonyo_school.db')
    c = conn.cursor()

    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'add':
            name = request.form.get('name').strip()
            grade = request.form.get('grade').strip()
            
            if not name or not grade:
                flash('Name and grade are required.', 'danger')
            elif len(name) > 50 or len(grade) > 10:  # Arbitrary limits
                flash('Name and grade must be within character limits.', 'danger')
            else:
                try:
                    c.execute("INSERT INTO learning_areas (name, grade) VALUES (?, ?)", (name, grade))
                    conn.commit()
                    flash('Learning area added successfully.', 'success')
                except sqlite3.IntegrityError:
                    flash('A learning area with this name and grade already exists.', 'danger')
        
        elif action == 'delete':
            area_id = request.form.get('area_id')
            if area_id:
                c.execute("DELETE FROM learning_areas WHERE id=?", (area_id,))
                conn.commit()
                flash('Learning area deleted successfully.', 'success')

    # Fetch all learning areas
    c.execute("SELECT id, name, grade FROM learning_areas")
    learning_areas = c.fetchall()
    conn.close()

    return render_template('manage_learning_areas.html', learning_areas=learning_areas)

@app.route('/view_teacher_marks', methods=['GET', 'POST'])
def view_teacher_marks():
    if 'role' not in session or session['role'] != 'teacher':
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('jonyo_school.db')
    c = conn.cursor()
    
    # Verify teacher exists
    c.execute("SELECT id, full_name FROM users WHERE id=? AND role='teacher'", (session['user_id'],))
    teacher = c.fetchone()
    if not teacher:
        conn.close()
        flash('Teacher profile not found. Contact admin.', 'danger')
        return redirect(url_for('teacher_dashboard'))
    
    teacher_id = teacher[0]
    
    # Fetch assigned grades and learning area IDs
    c.execute("SELECT DISTINCT la.grade, la.id FROM teacher_assignments ta JOIN learning_areas la ON ta.learning_area_id=la.id WHERE ta.teacher_id=?", (teacher_id,))
    assignments = c.fetchall()
    allowed_grades = sorted(list(set(assignment[0] for assignment in assignments)))
    allowed_learning_area_ids = [assignment[1] for assignment in assignments]
    
    if not allowed_grades or not allowed_learning_area_ids:
        conn.close()
        flash('No assigned classes or learning areas found.', 'warning')
        return redirect(url_for('teacher_dashboard'))
    
    # Initialize simple form
    class MarksFilterForm(FlaskForm):
        grade = SelectField('Grade', choices=[(g, g) for g in allowed_grades], default=allowed_grades[0])
        term = SelectField('Term', choices=[('Term 1', 'Term 1'), ('Term 2', 'Term 2'), ('Term 3', 'Term 3')], default='Term 1')
        submit = SubmitField('View Marks')
    
    form = MarksFilterForm()
    
    # Get filter values
    selected_grade = form.grade.data if form.validate_on_submit() else allowed_grades[0]
    selected_term = form.term.data if form.validate_on_submit() else 'Term 1'
    
    # Check if points column exists
    c.execute("PRAGMA table_info(marks)")
    columns = [info[1] for info in c.fetchall()]
    points_available = 'points' in columns
    
    # Query marks with dynamic points calculation if needed
    if points_available:
        query = """
            SELECT l.full_name, l.admission_no, la.name, m.marks, m.exam_type, COALESCE(m.points, 0) AS points
            FROM marks m
            JOIN learners l ON m.learner_admission=l.admission_no
            JOIN learning_areas la ON m.learning_area_id=la.id
            WHERE m.learning_area_id IN ({})
            AND l.grade=?
            AND m.term=?
        """
    else:
        query = """
            SELECT l.full_name, l.admission_no, la.name, m.marks, m.exam_type,
                   (SELECT pl.points FROM performance_levels pl WHERE m.marks BETWEEN pl.min_mark AND pl.max_mark) AS points
            FROM marks m
            JOIN learners l ON m.learner_admission=l.admission_no
            JOIN learning_areas la ON m.learning_area_id=la.id
            WHERE m.learning_area_id IN ({})
            AND l.grade=?
            AND m.term=?
        """
    query = query.format(','.join(['?'] * len(allowed_learning_area_ids)))
    
    params = allowed_learning_area_ids + [selected_grade, selected_term]
    
    c.execute(query, params)
    marks = c.fetchall()
    
    conn.close()
    
    return render_template('view_teacher_marks.html',
                           form=form,
                           marks=marks,
                           selected_grade=selected_grade,
                           selected_term=selected_term,
                           teacher_name=teacher[1])
    
@app.route('/view_class_exam_results', methods=['GET', 'POST'])
@login_required
def view_class_exam_results():
    if session.get('role') != 'admin':
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('jonyo_school.db')
    c = conn.cursor()
    
    results = []
    learners = []
    learning_areas = []
    selected_grade = request.args.get('grade') or request.form.get('grade')
    selected_exam_type = request.args.get('exam_type') or request.form.get('exam_type')
    selected_term = request.args.get('term') or request.form.get('term')
    selected_year = request.args.get('year') or request.form.get('year')
    
    if selected_grade and selected_exam_type and selected_term and selected_year:
        # Fetch learners in the selected grade
        c.execute("SELECT admission_no, full_name FROM learners WHERE grade=?", (selected_grade,))
        learners = c.fetchall()
        
        # Fetch learning areas for the grade
        c.execute("SELECT id, name FROM learning_areas WHERE grade=?", (selected_grade,))
        learning_areas = c.fetchall()
        learning_area_ids = [la[0] for la in learning_areas]
        
        if learning_area_ids:
            # Create placeholders for IN clause
            placeholders = ','.join('?' * len(learning_area_ids))
            query = f"""
                SELECT l.full_name, l.admission_no, la.name, m.marks, m.exam_type,
                       (SELECT pl.points FROM performance_levels pl WHERE m.marks BETWEEN pl.min_mark AND pl.max_mark) AS points
                FROM marks m
                JOIN learners l ON m.learner_admission = l.admission_no
                JOIN learning_areas la ON m.learning_area_id = la.id
                WHERE m.learning_area_id IN ({placeholders})
                AND l.grade = ?
                AND m.exam_type = ?
                AND m.term = ?
                AND m.year = ?
            """
            params = learning_area_ids + [selected_grade, selected_exam_type, selected_term, selected_year]
            c.execute(query, params)
            marks_data = c.fetchall()
            
            # Pivot results: [full_name, admission_no, mark_subject1, mark_subject2, ..., points_subject1, points_subject2, ...]
            for learner in learners:
                learner_result = [learner[1], learner[0]]  # [full_name, admission_no]
                total_points = 0
                for la in learning_areas:
                    mark_entry = next((m for m in marks_data if m[1] == learner[0] and m[2] == la[1]), None)
                    mark = mark_entry[3] if mark_entry else "-"
                    points = mark_entry[5] if mark_entry and mark_entry[5] is not None else "-"
                    learner_result.append(mark)
                    learner_result.append(points)
                    if isinstance(points, (int, float)):
                        total_points += points
                learner_result.append(total_points)
                results.append(learner_result)
            
            if not results:
                flash('No results found for this grade, exam type, term, and year.', 'warning')
        else:
            flash('No learning areas found for this grade.', 'warning')
    
    conn.close()
    return render_template('view_class_exam_results.html', results=results, learners=learners, 
                          learning_areas=learning_areas, selected_grade=selected_grade, 
                          selected_exam_type=selected_exam_type, selected_term=selected_term, 
                          selected_year=selected_year)
if __name__ == '__main__':
    app.run(debug=True)
