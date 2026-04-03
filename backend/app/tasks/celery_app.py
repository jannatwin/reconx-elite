from celery import Celery
from celery.schedules import crontab

from app.core.config import settings

celery_app = Celery(
    "reconx",
    broker=settings.redis_url,
    backend=settings.redis_url,
    include=[
        "app.tasks.scan_tasks",
        "app.tasks.advanced_recon_tasks",
        "app.tasks.validation_tasks",
        "app.tasks.learning_tasks",
    ],
)
celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    task_soft_time_limit=1200,
    task_time_limit=1500,
    beat_schedule={
        "check-scheduled-scans": {
            "task": "app.tasks.scan_tasks.check_scheduled_scans",
            "schedule": crontab(minute=f"*/{settings.scheduled_scan_poll_minutes}"),
        },
    },
)
celery_app.autodiscover_tasks(["app.tasks"])
