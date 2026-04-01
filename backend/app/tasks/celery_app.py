from celery import Celery
from celery.schedules import crontab

from app.core.config import settings

celery_app = Celery("reconx", broker=settings.redis_url, backend=settings.redis_url)
celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    beat_schedule={
        "check-scheduled-scans": {
            "task": "app.tasks.scan_tasks.check_scheduled_scans",
            "schedule": crontab(minute="*/10"),  # Every 10 minutes
        },
    },
)
celery_app.autodiscover_tasks(["app.tasks"])
