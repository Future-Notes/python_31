# worker.py
import time
import importlib
from datetime import datetime, timedelta

from app import app, db, Task

def import_callable(path):
    """
    Given "module.sub:func", import module.sub and return .func
    """
    module_path, fn_name = path.split(':', 1)
    module = importlib.import_module(module_path)
    return getattr(module, fn_name)

def main(poll_interval=60):
    with app.app_context():
        while True:
            now = datetime.utcnow()
            pending = (Task.query
                        .filter(Task.next_run <= now)
                        .order_by(Task.next_run)
                        .all())
            for task in pending:
                try:
                    fn = import_callable(task.function_path)
                    args = task.args or []
                    kwargs = task.kwargs or {}
                    fn(*args, **kwargs)
                except Exception as e:
                    app.logger.exception(f"Task {task.id} failed")
                # reschedule
                task.schedule_next()
                db.session.add(task)
            db.session.commit()
            time.sleep(poll_interval)

if __name__ == "__main__":
    # optional: read env var or arg for poll_interval
    main()
