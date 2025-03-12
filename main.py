from flask import Flask, render_template, redirect, url_for, request, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
import datetime
from zoneinfo import ZoneInfo  # for timezone support

# Initialize SQLAlchemy (without app context)
db = SQLAlchemy()

# Define task groups:
# Group 1: المهام اليومية (Daily Tasks) – each gives 10 points
DAILY_TASKS = [
    "السنن (3 على الاقل)",
    "صلاة الفجر",
    "500 ذكر الله",
    "300 صلاة على النبي",
    "الصلاة في جماعة (3 على الاقل)",
    "الدعاء",
    "الإفطار على سنة النبي",
    "إفطار صائم",
    "اذكار الصلاة",
    "قيام الليل"
]

# Group 2: التحديات (Challenge Tasks) – with custom points
CHALLENGE_TASKS = [
    ("صلاة التراويح", 50),
    ("اذكار الصباح والمساء", 50),
    ("الشفع و الوتر", 20),
    ("قراءة جزء من القرآن", 80)
]

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    tasks = db.relationship('UserTask', backref='user', lazy=True)

class UserTask(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    task_name = db.Column(db.String(100), nullable=False)
    # Stored as an offset-naive datetime
    vote_time = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    points = db.Column(db.Integer, nullable=False, default=10)
    task_type = db.Column(db.String(20), nullable=False, default="daily")  # "daily" or "challenge"

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'your_secret_key'  # Replace with a strong secret key
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
    
    db.init_app(app)
    Migrate(app, db)
    
    with app.app_context():
        db.create_all()

    @app.route('/')
    def index():
        if 'user_id' in session:
            return redirect(url_for('vote'))
        return redirect(url_for('login'))

    @app.route('/signup', methods=['GET', 'POST'])
    def signup():
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']
            if User.query.filter_by(username=username).first():
                flash('Username already exists! Please choose another.')
                return redirect(url_for('signup'))
            if len(password) < 6:
                flash('Password must be at least 6 characters long.')
                return redirect(url_for('signup'))
            hashed_password = generate_password_hash(password)
            new_user = User(username=username, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            flash('Signup successful! Please log in.')
            return redirect(url_for('login'))
        return render_template('signup.html')

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']
            user = User.query.filter_by(username=username).first()
            if user and check_password_hash(user.password, password):
                session['user_id'] = user.id
                flash('Logged in successfully!')
                return redirect(url_for('vote'))
            else:
                flash('Invalid credentials!')
                return redirect(url_for('login'))
        return render_template('login.html')

    @app.route('/logout')
    def logout():
        session.pop('user_id', None)
        flash('Logged out.')
        return redirect(url_for('login'))

    @app.route('/vote', methods=['GET', 'POST'])
    def vote():
        if 'user_id' not in session:
            flash('Please log in first.')
            return redirect(url_for('login'))
        user = User.query.get(session['user_id'])
        if user is None:
            flash('User not found. Please log in again.')
            session.pop('user_id', None)
            return redirect(url_for('login'))
        
        # Get current time in Cairo (offset-aware)
        now = datetime.datetime.now(ZoneInfo("Africa/Cairo"))
        # Set reset time to 8:00 PM Cairo time (offset-aware)
        today_reset = now.replace(hour=20, minute=0, second=0, microsecond=0)
        period_start = today_reset - datetime.timedelta(days=1) if now < today_reset else today_reset
        # Convert to offset-naive for comparison (since vote_time is stored as naive)
        period_start_naive = period_start.replace(tzinfo=None)

        # Map English weekday names to Arabic
        day_mapping = {
            "Saturday": "السبت",
            "Sunday": "الأحد",
            "Monday": "الإثنين",
            "Tuesday": "الثلاثاء",
            "Wednesday": "الأربعاء",
            "Thursday": "الخميس",
            "Friday": "الجمعة"
        }
        voting_day = day_mapping.get(period_start.strftime("%A"), period_start.strftime("%A"))

        # Retrieve voted tasks for current period using the naive period_start
        voted_daily = [ut.task_name for ut in user.tasks if ut.vote_time >= period_start_naive and ut.task_type == "daily"]
        voted_challenge = [ut.task_name for ut in user.tasks if ut.vote_time >= period_start_naive and ut.task_type == "challenge"]

        # Remove duplicates
        voted_daily = list(dict.fromkeys(voted_daily))
        voted_challenge = list(dict.fromkeys(voted_challenge))

        available_daily = [task for task in DAILY_TASKS if task not in voted_daily]
        available_challenge = [task for task, pts in CHALLENGE_TASKS if task not in voted_challenge]
        
        # Calculate total points for user
        total_points = sum(ut.points for ut in user.tasks)
        
        if request.method == 'POST':
            # Use Cairo time and convert to naive when storing
            current_vote_time = datetime.datetime.now(ZoneInfo("Africa/Cairo")).replace(tzinfo=None)
            selected_daily = request.form.getlist('daily_tasks')
            for task in selected_daily:
                if task in DAILY_TASKS and task not in voted_daily:
                    new_vote = UserTask(
                        task_name=task,
                        user_id=user.id,
                        vote_time=current_vote_time,
                        points=10,
                        task_type="daily"
                    )
                    db.session.add(new_vote)
            selected_challenge = request.form.getlist('challenge_tasks')
            for task in selected_challenge:
                if task in [t for t, pts in CHALLENGE_TASKS] and task not in voted_challenge:
                    pts = next(pts for t, pts in CHALLENGE_TASKS if t == task)
                    new_vote = UserTask(
                        task_name=task,
                        user_id=user.id,
                        vote_time=current_vote_time,
                        points=pts,
                        task_type="challenge"
                    )
                    db.session.add(new_vote)
            db.session.commit()
            flash('Votes recorded!')
            return redirect(url_for('vote'))
        
        return render_template('vote.html', 
                               available_daily=available_daily, 
                               voted_daily=voted_daily,
                               available_challenge=available_challenge,
                               voted_challenge=voted_challenge,
                               challenge_tasks=CHALLENGE_TASKS,
                               total_points=total_points,
                               voting_day=voting_day)

    @app.route('/leaderboard')
    def leaderboard():
        users = User.query.all()
        leaderboard_data = []
        current_user_id = session.get('user_id')
        
        for user in users:
            total_points = sum(ut.points for ut in user.tasks)
            daily_count = len([ut for ut in user.tasks if ut.task_type == "daily"])
            challenge_count = len([ut for ut in user.tasks if ut.task_type == "challenge"])
            
            leaderboard_data.append({
                'username': user.username,
                'daily_count': daily_count,
                'challenge_count': challenge_count,
                'points': total_points,
                'is_current_user': user.id == current_user_id
            })
        
        leaderboard_data.sort(key=lambda x: x['points'], reverse=True)
        
        # Find current user's rank
        user_rank = None
        user_data = None
        
        if current_user_id:
            for index, entry in enumerate(leaderboard_data):
                if entry['is_current_user']:
                    user_rank = index + 1
                    user_data = entry
                    break
        
        return render_template('leaderboard.html', 
                               leaderboard=leaderboard_data, 
                               user_rank=user_rank,
                               user_data=user_data)
    
    @app.route('/tasks')
    def tasks_page():
        daily_tasks_info = [(task, 10) for task in DAILY_TASKS]
        total_challenge_points = sum(pts for _, pts in CHALLENGE_TASKS)
        
        return render_template('tasks.html', 
                               daily_tasks=daily_tasks_info, 
                               challenge_tasks=CHALLENGE_TASKS,
                               total_challenge_points=total_challenge_points)

    @app.route('/history')
    def history():
        if 'user_id' not in session:
            flash('Please log in first.')
            return redirect(url_for('login'))
        user = User.query.get(session['user_id'])
        if user is None:
            flash('User not found. Please log in again.')
            session.pop('user_id', None)
            return redirect(url_for('login'))
        # Group tasks by day
        history = {}
        for task in user.tasks:
            day = task.vote_time.strftime("%Y-%m-%d")
            history.setdefault(day, []).append(task)
        # Sort tasks within each day (latest first) and sort days descending
        for day in history:
            history[day].sort(key=lambda t: t.vote_time, reverse=True)
        sorted_history = dict(sorted(history.items(), key=lambda item: item[0], reverse=True))
        return render_template('history.html', history=sorted_history)

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True)
