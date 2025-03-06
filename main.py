from flask import Flask, render_template, redirect, url_for, request, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
import datetime

# Initialize SQLAlchemy (without app context)
db = SQLAlchemy()

# Define task groups:
# Group 1: المهام اليومية (Daily Tasks) – each gives 10 points
DAILY_TASKS = [
    "السنن (3 على الاقل)",
    "صلاة الفجر",
    "500 ذكر الله",
    "300 صلاة على النبي",
    "الصلاة في جماعة",
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
        
        # Determine the start of the current voting period (reset at 10:18 PM)
        now = datetime.datetime.now()
        today_reset = now.replace(hour=22, minute=18, second=0, microsecond=0)
        period_start = today_reset - datetime.timedelta(days=1) if now < today_reset else today_reset

        # Retrieve voted tasks for current period
        voted_daily = [ut.task_name for ut in user.tasks if ut.vote_time >= period_start and ut.task_type == "daily"]
        voted_challenge = [ut.task_name for ut in user.tasks if ut.vote_time >= period_start and ut.task_type == "challenge"]

        # Remove duplicates
        voted_daily = list(dict.fromkeys(voted_daily))
        voted_challenge = list(dict.fromkeys(voted_challenge))

        available_daily = [task for task in DAILY_TASKS if task not in voted_daily]
        available_challenge = [task for task, pts in CHALLENGE_TASKS if task not in voted_challenge]
        
        if request.method == 'POST':
            selected_daily = request.form.getlist('daily_tasks')
            for task in selected_daily:
                if task in DAILY_TASKS and task not in voted_daily:
                    new_vote = UserTask(
                        task_name=task,
                        user_id=user.id,
                        vote_time=datetime.datetime.now(),
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
                        vote_time=datetime.datetime.now(),
                        points=pts,
                        task_type="challenge"
                    )
                    db.session.add(new_vote)
            db.session.commit()
            flash('Votes recorded!')
            return redirect(url_for('vote'))
        
        # Pass challenge_tasks so that the template can display points for challenges
        return render_template('vote.html', 
                               available_daily=available_daily, 
                               voted_daily=voted_daily,
                               available_challenge=available_challenge,
                               voted_challenge=voted_challenge,
                               challenge_tasks=CHALLENGE_TASKS)

    @app.route('/leaderboard')
    def leaderboard():
        users = User.query.all()
        leaderboard_data = []
        for user in users:
            total_points = sum(ut.points for ut in user.tasks)
            daily_count = len([ut for ut in user.tasks if ut.task_type == "daily"])
            challenge_count = len([ut for ut in user.tasks if ut.task_type == "challenge"])
            leaderboard_data.append({
                'username': user.username,
                'daily_count': daily_count,
                'challenge_count': challenge_count,
                'points': total_points
            })
        leaderboard_data.sort(key=lambda x: x['points'], reverse=True)
        return render_template('leaderboard.html', leaderboard=leaderboard_data)
    
    # Read-only tasks page
    @app.route('/tasks')
    def tasks_page():
        daily_tasks_info = [(task, 10) for task in DAILY_TASKS]
        return render_template('tasks.html', 
                               daily_tasks=daily_tasks_info, 
                               challenge_tasks=CHALLENGE_TASKS)

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True)
