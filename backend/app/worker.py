from celery import Celery

from app.core.config import settings

celery_app = Celery("reconx", broker=settings.redis_url, backend=settings.redis_url)
celery_app.conf.update(task_track_started=True, timezone="UTC")

celery_app.autodiscover_tasks(["app"])
