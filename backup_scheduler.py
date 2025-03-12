import json
import datetime
import subprocess
from zoneinfo import ZoneInfo
from main import create_app, db, User, UserTask

def backup_database():
    # Get current Cairo time for file naming
    now_cairo = datetime.datetime.now(ZoneInfo("Africa/Cairo"))
    # File name includes the date (e.g., backup_2025-03-12.json)
    filename = f"backup_{now_cairo.strftime('%Y-%m-%d')}.json"
    app = create_app()
    with app.app_context():
        users = User.query.all()
        backup_data = {"users": []}
        for user in users:
            user_dict = {
                "id": user.id,
                "username": user.username,
                "tasks": []
            }
            for task in user.tasks:
                task_dict = {
                    "id": task.id,
                    "task_name": task.task_name,
                    "vote_time": task.vote_time.isoformat() if task.vote_time else None,
                    "points": task.points,
                    "task_type": task.task_type
                }
                user_dict["tasks"].append(task_dict)
            backup_data["users"].append(user_dict)
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(backup_data, f, ensure_ascii=False, indent=4)
        print(f"[{datetime.datetime.now()}] Database backup completed. File saved as '{filename}'.")
    return filename

def push_to_github(filename):
    try:
        # Stage only the backup file.
        subprocess.run(["git", "add", filename], check=True)

        # Check what files are staged
        diff = subprocess.run(
            ["git", "diff", "--cached", "--name-only"],
            capture_output=True,
            text=True,
            check=True
        )
        staged_files = diff.stdout.strip().splitlines()

        if filename not in staged_files:
            print(f"[{datetime.datetime.now()}] No changes to commit for {filename}.")
        else:
            commit_message = f"Daily backup: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            subprocess.run(["git", "commit", "-m", commit_message], check=True)
            print(f"[{datetime.datetime.now()}] Commit successful.")
        
        # Push the commit (or if no commit was made, push existing commits)
        subprocess.run(["git", "push"], check=True)
        print(f"[{datetime.datetime.now()}] Backup pushed to GitHub successfully.")
    except subprocess.CalledProcessError as e:
        print(f"[{datetime.datetime.now()}] Error during git operations: {e}")

def backup_and_push():
    filename = backup_database()
    push_to_github(filename)

if __name__ == '__main__':
    backup_and_push()
