import sys
import os
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import datetime
from datetime import timedelta
import webview
from functools import wraps
import threading
import time
from winotify import Notification, audio

# --- Resource Path Helper ---
def resource_path(relative_path):
    """Get absolute path to resource, works for dev and PyInstaller"""
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

template_folder = resource_path('templates')
static_folder = resource_path('static')

app = Flask(__name__, template_folder=template_folder, static_folder=static_folder)

# --- Enhanced Security Config ---
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your_secret_key_here_change_in_production')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///studyspace.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=12)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# --- Notification System ---
notification_thread = None
stop_notifications = threading.Event()

def check_upcoming_reservations():
    """Background thread that checks for upcoming reservations and sends notifications"""
    notified_start = set()  # Track which reservations we've already notified about (start)
    notified_end = set()    # Track which reservations we've already notified about (end)
    
    while not stop_notifications.is_set():
        try:
            with app.app_context():
                now = datetime.datetime.now()
                print(f"\n[DEBUG] Checking notifications at {now.strftime('%H:%M:%S')}")
                
                # Get all active reservations
                active_reservations = Reservation.query.filter(
                    Reservation.status.in_(['Confirmed', 'Checked In'])
                ).all()
                
                print(f"[DEBUG] Found {len(active_reservations)} active reservations")
                
                for res in active_reservations:
                    # Parse reservation time
                    res_date = datetime.datetime.strptime(res.date, "%Y-%m-%d").date()
                    start_str = res.time_slot.split(' - ')[0]
                    end_str = res.time_slot.split(' - ')[1]
                    
                    res_start = datetime.datetime.combine(res_date, datetime.datetime.strptime(start_str, "%H:%M").time())
                    res_end = datetime.datetime.combine(res_date, datetime.datetime.strptime(end_str, "%H:%M").time())
                    
                    # Handle reservations that end on the next day (e.g. 23:00 - 00:00)
                    if res_end < res_start:
                        res_end += timedelta(days=1)
                    
                    # Check for 10 minutes before start
                    time_until_start = (res_start - now).total_seconds()
                    start_key = f"start_{res.id}"
                    
                    print(f"[DEBUG] Reservation {res.id} - {res.space_name} at {res.time_slot}")
                    print(f"        Time until start: {time_until_start/60:.1f} minutes")
                    
                    # 10 minutes = 600 seconds, check within a 20-second window (590-610)
                    if 590 <= time_until_start <= 610 and start_key not in notified_start:
                        user = db.session.get(User, res.user_id)
                        if user:
                            print(f"[NOTIFICATION] Sending START notification for {res.space_name}")
                            toast = Notification(
                                app_id="StudySpace+",
                                title="StudySpace+ Reminder",
                                msg=f"Your reservation at {res.space_name} starts in 10 minutes!\nTime: {res.time_slot}",
                                duration="long"
                            )
                            toast.set_audio(audio.Default, loop=False)
                            toast.show()
                            notified_start.add(start_key)
                    
                    # Check for 10 minutes before end
                    time_until_end = (res_end - now).total_seconds()
                    end_key = f"end_{res.id}"
                    
                    print(f"        Time until end: {time_until_end/60:.1f} minutes")
                    
                    # 10 minutes = 600 seconds, check within a 20-second window (590-610)
                    if 590 <= time_until_end <= 610 and end_key not in notified_end:
                        user = db.session.get(User, res.user_id)
                        if user:
                            print(f"[NOTIFICATION] Sending END notification for {res.space_name}")
                            toast = Notification(
                                app_id="StudySpace+",
                                title="StudySpace+ Reminder",
                                msg=f"Your reservation at {res.space_name} ends in 10 minutes!\nTime: {res.time_slot}\nPlease wrap up.",
                                duration="long"
                            )
                            toast.set_audio(audio.Default, loop=False)
                            toast.show()
                            notified_end.add(end_key)
                    
                    # Clean up old notifications from memory
                    if time_until_end < -3600:  # 1 hour after end
                        notified_start.discard(start_key)
                        notified_end.discard(end_key)
        
        except Exception as e:
            print(f"Notification error: {e}")
        
        # Check every 30 seconds
        time.sleep(30)

def start_notification_service():
    """Start the background notification checker"""
    global notification_thread
    if notification_thread is None or not notification_thread.is_alive():
        stop_notifications.clear()
        notification_thread = threading.Thread(target=check_upcoming_reservations, daemon=True)
        notification_thread.start()
        print(">>> Notification service started")

# --- User Loader ---
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# --- Database Models (Compatible with existing DB) ---
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    firstname = db.Column(db.String(50), nullable=False)
    lastname = db.Column(db.String(50), nullable=False)
    student_id = db.Column(db.String(20), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password, method='pbkdf2:sha256')
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Reservation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref='reservations')
    space_name = db.Column(db.String(100), nullable=False)
    block_name = db.Column(db.String(10), nullable=False)
    date = db.Column(db.String(20), nullable=False)
    time_slot = db.Column(db.String(20), nullable=False)
    group_size = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(20), default='Confirmed', nullable=False)

# --- Constants ---
TIME_SLOTS = [
    "09:00 - 10:00", "10:00 - 11:00", "11:00 - 12:00",
    "12:00 - 13:00", "13:00 - 14:00", "14:00 - 15:00",
    "15:00 - 16:00", "16:00 - 17:00", "17:00 - 18:00",
    "18:00 - 19:00", "19:00 - 20:00", "20:00 - 21:00",
    "21:00 - 22:00", "22:00 - 23:00", "23:00 - 00:00"
]

spaces = [
    # Block A
    {"id": 11, "name": "Room A200", "block": "A", "capacity": 30, "status": "available"},
    {"id": 12, "name": "Room A201", "block": "A", "capacity": 30, "status": "reserved"},
    {"id": 13, "name": "Room A202", "block": "A", "capacity": 30, "status": "available"},
    {"id": 14, "name": "Room A203", "block": "A", "capacity": 15, "status": "available"},
    {"id": 15, "name": "Room A204", "block": "A", "capacity": 15, "status": "available"},
    
    # Block C
    {"id": 30, "name": "Room CB50", "block": "C", "capacity": 20, "status": "available"},
    {"id": 31, "name": "Room CB51", "block": "C", "capacity": 20, "status": "reserved"},
    {"id": 32, "name": "Room CB52", "block": "C", "capacity": 20, "status": "available"},
    {"id": 33, "name": "Room CB53", "block": "C", "capacity": 20, "status": "available"},
    {"id": 34, "name": "Room CB54", "block": "C", "capacity": 20, "status": "available"},
    {"id": 35, "name": "Room CB55", "block": "C", "capacity": 20, "status": "available"},
    {"id": 36, "name": "Room CZ9", "block": "C", "capacity": 50, "status": "available"},
    {"id": 37, "name": "Room CZ10", "block": "C", "capacity": 50, "status": "reserved"},
    {"id": 38, "name": "Room CZ11", "block": "C", "capacity": 50, "status": "available"},
    {"id": 39, "name": "Room CZ12", "block": "C", "capacity": 50, "status": "available"},
    {"id": 40, "name": "Room C208", "block": "C", "capacity": 20, "status": "available"},
    {"id": 41, "name": "Room C209", "block": "C", "capacity": 20, "status": "available"},
    {"id": 42, "name": "Room C210", "block": "C", "capacity": 20, "status": "reserved"},
    {"id": 43, "name": "Room C211", "block": "C", "capacity": 20, "status": "available"},
    {"id": 44, "name": "Room C212", "block": "C", "capacity": 20, "status": "available"},
    {"id": 45, "name": "Room C213", "block": "C", "capacity": 20, "status": "available"},
    {"id": 46, "name": "Room C214", "block": "C", "capacity": 20, "status": "available"},
    {"id": 47, "name": "Room C215", "block": "C", "capacity": 20, "status": "reserved"},
    {"id": 48, "name": "Room C315", "block": "C", "capacity": 20, "status": "available"},
    {"id": 49, "name": "Room C316", "block": "C", "capacity": 20, "status": "available"},
    {"id": 50, "name": "Room C317", "block": "C", "capacity": 20, "status": "available"},
    {"id": 51, "name": "Room C318", "block": "C", "capacity": 20, "status": "reserved"},
    {"id": 52, "name": "Room C319", "block": "C", "capacity": 20, "status": "available"},
    {"id": 53, "name": "Room C320", "block": "C", "capacity": 20, "status": "available"},
    {"id": 54, "name": "Room C412", "block": "C", "capacity": 20, "status": "available"},
    {"id": 55, "name": "Room C413", "block": "C", "capacity": 20, "status": "available"},
    {"id": 56, "name": "Room C414", "block": "C", "capacity": 20, "status": "reserved"},
    {"id": 57, "name": "Room C415", "block": "C", "capacity": 20, "status": "available"},
]

# --- Helper Functions ---
def admin_required(f):
    """Decorator for admin-only routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or not session.get('is_admin'):
            flash("Access Denied: Admins only.", "error")
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# --- Security Middleware ---
@app.before_request
def check_user_validity():
    """Validate user session before each request"""
    if request.endpoint and 'static' in request.endpoint:
        return
    
    if 'user_id' in session:
        user = db.session.get(User, session['user_id'])
        if user is None:
            session.clear()
            flash("Your account has been deactivated.", "error")
            return redirect(url_for('login'))

# --- Routes ---
@app.route('/')
def root():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        if not username or not password:
            flash("Please enter both username and password.", "error")
            return redirect(url_for('login'))
        
        user = User.query.filter_by(student_id=username).first()
        
        if user and user.check_password(password):
            session.permanent = True
            session['user_id'] = user.id
            session['user_name'] = user.firstname
            session['is_admin'] = user.is_admin
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid Username or Password", "error")
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        firstname = request.form.get('firstname', '').strip()
        lastname = request.form.get('lastname', '').strip()
        student_id = request.form.get('student_id', '').strip()
        password = request.form.get('password', '')
        
        # Validation
        if not all([firstname, lastname, student_id, password]):
            flash('All fields are required!', 'error')
            return redirect(url_for('register'))
        
        if len(password) < 6:
            flash('Password must be at least 6 characters long.', 'error')
            return redirect(url_for('register'))
        
        # Check if user exists
        if User.query.filter_by(student_id=student_id).first():
            flash('Username already exists!', 'error')
            return redirect(url_for('register'))
        
        # Create new user
        new_user = User(
            firstname=firstname,
            lastname=lastname,
            student_id=student_id,
            is_admin=False
        )
        new_user.set_password(password)
        
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    blocks = ["A", "C"]
    return render_template('dashboard.html', 
                         blocks=blocks, 
                         name=session.get('user_name'))

@app.route('/block/<block_name>')
def show_classrooms(block_name):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if block_name not in ["A", "C"]:
        flash("Invalid block selected.", "error")
        return redirect(url_for('dashboard'))
    
    filtered_spaces = [s.copy() for s in spaces if s['block'] == block_name]
    
    today = datetime.date.today()
    tomorrow = today + timedelta(days=1)
    str_today = today.strftime("%Y-%m-%d")
    str_tomorrow = tomorrow.strftime("%Y-%m-%d")
    
    # Identify past time slots for today
    current_hour = datetime.datetime.now().hour
    past_slots_today = []
    for slot in TIME_SLOTS:
        start_hour = int(slot.split(':')[0])
        if start_hour <= current_hour:
            past_slots_today.append(slot)
    
    # Fetch active reservations
    reservations = Reservation.query.filter(
        Reservation.block_name == block_name,
        Reservation.date.in_([str_today, str_tomorrow])
    ).all()
    
    # Calculate occupancy (only count Confirmed and Checked In)
    occupancy = {str_today: {}, str_tomorrow: {}}
    for res in reservations:
        if res.status in ['Confirmed', 'Checked In']:
            if res.space_name not in occupancy[res.date]:
                occupancy[res.date][res.space_name] = {}
            if res.time_slot not in occupancy[res.date][res.space_name]:
                occupancy[res.date][res.space_name][res.time_slot] = 0
            occupancy[res.date][res.space_name][res.time_slot] += res.group_size
    
    # Identify full slots
    full_slots_data = {str_today: {}, str_tomorrow: {}}
    for space in filtered_spaces:
        cap = space['capacity']
        s_name = space['name']
        full_slots_data[str_today][s_name] = []
        full_slots_data[str_tomorrow][s_name] = []
        
        # Check today (with time validation)
        for slot in TIME_SLOTS:
            # 1. Check if time has passed
            if slot in past_slots_today:
                full_slots_data[str_today][s_name].append(slot)
                continue
            
            # 2. Check capacity
            booked_count = occupancy[str_today].get(s_name, {}).get(slot, 0)
            if booked_count >= cap:
                full_slots_data[str_today][s_name].append(slot)
        
        # Check tomorrow (capacity only)
        for slot, count in occupancy[str_tomorrow].get(s_name, {}).items():
            if count >= cap:
                full_slots_data[str_tomorrow][s_name].append(slot)
        
        # Update visual status
        if len(full_slots_data[str_today][s_name]) >= len(TIME_SLOTS):
            space['status'] = 'reserved'
        else:
            space['status'] = 'available'
    
    return render_template('classrooms.html',
                         spaces=filtered_spaces,
                         current_block=block_name,
                         time_slots=TIME_SLOTS,
                         booked_data=full_slots_data,
                         date_today=str_today,
                         date_tomorrow=str_tomorrow)

@app.route('/reserve', methods=['POST'])
def reserve():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    space_name = request.form.get('space_name')
    block_name = request.form.get('block_name')
    group_size_str = request.form.get('group_size', '0')
    time_slot = request.form.get('time_slot')
    selected_date = request.form.get('selected_date')
    
    # Validate group size
    try:
        group_size = int(group_size_str)
        if group_size <= 0:
            raise ValueError
    except ValueError:
        flash("Invalid group size.", "error")
        return redirect(url_for('show_classrooms', block_name=block_name))

    # Check for past time slots
    date_today = datetime.date.today().strftime("%Y-%m-%d")
    current_hour = datetime.datetime.now().hour
    slot_start = int(time_slot.split(':')[0])

    if selected_date == date_today and slot_start <= current_hour:
        return render_template('reservation_error.html', 
                               space_name=space_name, 
                               time_slot=time_slot, 
                               block_name=block_name)

    # Find capacity
    capacity = 0
    for s in spaces:
        if s['name'] == space_name:
            capacity = s['capacity']
            break

    if capacity == 0 or group_size > capacity:
        return render_template('reservation_error.html', 
                               space_name=space_name, 
                               time_slot=time_slot, 
                               block_name=block_name)

    # Check existing reservations (only active ones)
    existing_res = Reservation.query.filter_by(
        space_name=space_name, 
        date=selected_date, 
        time_slot=time_slot
    ).filter(Reservation.status.in_(['Confirmed', 'Checked In'])).all()
    
    current_occupancy = sum(r.group_size for r in existing_res)

    if current_occupancy + group_size > capacity:
        return render_template('reservation_error.html', 
                               space_name=space_name, 
                               time_slot=time_slot, 
                               block_name=block_name)

    # Create reservation
    new_res = Reservation(
        user_id=session['user_id'],
        space_name=space_name,
        block_name=block_name,
        date=selected_date,
        time_slot=time_slot,
        group_size=group_size,
        status='Confirmed'
    )
    db.session.add(new_res)
    db.session.commit()

    return redirect(url_for('my_reservations'))

@app.route('/my_reservations')
def my_reservations():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    now = datetime.datetime.now()
    
    # Fetch user's reservations
    all_reservations = Reservation.query.filter_by(user_id=session['user_id'])\
        .order_by(Reservation.date, Reservation.time_slot).all()
        
    # Auto-update statuses and separate reservations
    active_reservations = []
    past_reservations = []

    for res in all_reservations:
        # Parse dates
        res_date_obj = datetime.datetime.strptime(res.date, "%Y-%m-%d").date()
        start_str = res.time_slot.split(' - ')[0]
        end_str = res.time_slot.split(' - ')[1]
        
        res_start_dt = datetime.datetime.combine(res_date_obj, datetime.datetime.strptime(start_str, "%H:%M").time())
        res_end_dt = datetime.datetime.combine(res_date_obj, datetime.datetime.strptime(end_str, "%H:%M").time())

        # Auto-update: Handle "Confirmed" (No Shows)
        if res.status == 'Confirmed':
            checkin_deadline = res_start_dt + timedelta(minutes=10)
            if now > checkin_deadline:
                res.status = "No Show"
                db.session.commit()

        # Auto-update: Handle "Checked In" (Completion)
        elif res.status == 'Checked In':
            if now > res_end_dt:
                res.status = "Completed"
                db.session.commit()

        # Separate active vs history
        if res.status in ['Cancelled', 'Completed', 'No Show', 'Expired']:
            past_reservations.append(res)
        else:
            active_reservations.append(res)

    # Reverse past reservations (most recent first)
    past_reservations.reverse()

    return render_template('my_reservations.html', 
                           active_reservations=active_reservations, 
                           past_reservations=past_reservations)

@app.route('/check_in/<int:res_id>', methods=['POST'])
def check_in(res_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    reservation = db.session.get(Reservation, res_id)
    
    if not reservation or reservation.user_id != session['user_id']:
        flash("Reservation not found.", "error")
        return redirect(url_for('my_reservations'))
    
    if reservation.status != 'Confirmed':
        flash("This reservation cannot be checked in.", "warning")
        return redirect(url_for('my_reservations'))
    
    # Check if within check-in window (15 min before to 10 min after start)
    res_date = datetime.datetime.strptime(reservation.date, "%Y-%m-%d").date()
    start_time = datetime.datetime.strptime(reservation.time_slot.split(' - ')[0], "%H:%M").time()
    res_start = datetime.datetime.combine(res_date, start_time)
    now = datetime.datetime.now()
    
    if not ((res_start - timedelta(minutes=15)) <= now <= (res_start + timedelta(minutes=10))):
        flash("Check-in is only available 15 minutes before to 10 minutes after the start time.", "warning")
        return redirect(url_for('my_reservations'))
    
    reservation.status = "Checked In"
    db.session.commit()
    flash("You have successfully checked in!", "success")
    
    return redirect(url_for('my_reservations'))

@app.route('/cancel_reservation/<int:res_id>', methods=['POST'])
def cancel_reservation(res_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    reservation = db.session.get(Reservation, res_id)
    
    if not reservation or reservation.user_id != session['user_id']:
        flash("Reservation not found.", "error")
        return redirect(url_for('my_reservations'))
    
    if reservation.status not in ['Confirmed', 'Checked In']:
        flash("This reservation cannot be cancelled.", "warning")
        return redirect(url_for('my_reservations'))
    
    reservation.status = "Cancelled"
    db.session.commit()
    
    return redirect(url_for('my_reservations'))

# --- Admin Routes ---
@app.route('/admin')
@admin_required
def admin_dashboard():
    now = datetime.datetime.now()
    
    # Fetch all reservations
    all_reservations = Reservation.query.order_by(Reservation.date.desc(), Reservation.time_slot.desc()).all()
    all_users = User.query.all()
    
    active_reservations = []
    history_reservations = []

    # Auto-update statuses and separate
    for res in all_reservations:
        res_date_obj = datetime.datetime.strptime(res.date, "%Y-%m-%d").date()
        start_str = res.time_slot.split(' - ')[0] 
        end_str = res.time_slot.split(' - ')[1]   
        
        res_start_dt = datetime.datetime.combine(res_date_obj, datetime.datetime.strptime(start_str, "%H:%M").time())
        res_end_dt = datetime.datetime.combine(res_date_obj, datetime.datetime.strptime(end_str, "%H:%M").time())

        # Auto-update statuses
        if res.status == 'Confirmed':
            checkin_deadline = res_start_dt + timedelta(minutes=10)
            if now > checkin_deadline:
                res.status = "No Show"
                db.session.commit()
        
        elif res.status == 'Checked In':
            if now > res_end_dt:
                res.status = "Completed"
                db.session.commit()

        # Separate
        if res.status in ['Cancelled', 'Completed', 'No Show', 'Expired']:
            history_reservations.append(res)
        else:
            active_reservations.append(res)

    return render_template('admin_dashboard.html', 
                           active_reservations=active_reservations, 
                           history_reservations=history_reservations, 
                           users=all_users)

@app.route('/admin/delete_res/<int:res_id>', methods=['POST'])
@admin_required
def admin_delete_res(res_id):
    res = db.session.get(Reservation, res_id)
    if res:
        db.session.delete(res)
        db.session.commit()
        flash("Reservation deleted by Admin.", "success")
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@admin_required
def admin_delete_user(user_id):
    user = db.session.get(User, user_id)
    if user:
        if user.id == session['user_id']:
            flash("You cannot delete your own admin account!", "error")
        else:
            # Delete user's reservations first
            user_res = Reservation.query.filter_by(user_id=user.id).all()
            for r in user_res:
                db.session.delete(r)
            db.session.delete(user)
            db.session.commit()
            flash(f"User {user.student_id} deleted.", "success")
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/analytics')
@admin_required
def admin_analytics():
    all_res = Reservation.query.all()
    
    # Block popularity
    block_counts = {'A': 0, 'C': 0}
    for r in all_res:
        if r.block_name in block_counts:
            block_counts[r.block_name] += 1
    
    # Peak hours
    time_counts = {slot: 0 for slot in TIME_SLOTS}
    for r in all_res:
        if r.time_slot in time_counts:
            time_counts[r.time_slot] += 1
    
    # Convert for Chart.js
    block_labels = list(block_counts.keys())
    block_values = list(block_counts.values())
    time_labels = list(time_counts.keys())
    time_values = list(time_counts.values())
    
    return render_template('analytics.html', 
                           block_labels=block_labels, 
                           block_values=block_values,
                           time_labels=time_labels,
                           time_values=time_values)

# --- Application Startup ---
if __name__ == '__main__':
    with app.app_context():
        # Create database tables
        db.create_all()

        # Create/update admin user
        admin = User.query.filter_by(student_id='admin').first()
        if not admin:
            admin = User(
                student_id='admin',
                firstname='System',
                lastname='Admin',
                is_admin=True
            )
            admin.set_password('admin123')
            db.session.add(admin)
            db.session.commit()
            print(">>> Admin account created: User='admin', Pass='admin123'")
        else:
            print(">>> Admin account exists")
    
    # Start notification service
    start_notification_service()
    
    # Launch desktop application
    webview.create_window('StudySpace+', app)
    webview.start()