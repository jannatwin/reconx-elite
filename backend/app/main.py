from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from app import models  # noqa: F401
from app.core.config import settings
from app.core.database import Base, engine
from app.core.middleware import AuthGuardMiddleware, RequestLoggingMiddleware
from app.routers import auth, bookmarks, notifications, reports, scans, schedules, targets, vulnerabilities

# Ensure tables exist for local/dev setup.
Base.metadata.create_all(bind=engine)

app = FastAPI(title=settings.app_name)
app.add_middleware(SlowAPIMiddleware)
app.add_middleware(RequestLoggingMiddleware)
app.add_middleware(AuthGuardMiddleware)
=======
=======
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs

from app.db.session import Base, engine
from app.routers import auth, scans, targets
from app.utils.rate_limit import InMemoryRateLimitMiddleware

Base.metadata.create_all(bind=engine)

app = FastAPI(title="ReconX API")

<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
app.state.limiter = auth.limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.include_router(auth.router)
app.include_router(targets.router)
app.include_router(scans.router)
app.include_router(schedules.router)
app.include_router(notifications.router)
app.include_router(bookmarks.router)
app.include_router(vulnerabilities.router)
app.include_router(reports.router)
=======
app.add_middleware(InMemoryRateLimitMiddleware, max_requests=120, window_seconds=60)
>>>>>>> theirs
=======
app.add_middleware(InMemoryRateLimitMiddleware, max_requests=120, window_seconds=60)
>>>>>>> theirs
=======
app.add_middleware(InMemoryRateLimitMiddleware, max_requests=120, window_seconds=60)
>>>>>>> theirs
=======
app.add_middleware(InMemoryRateLimitMiddleware, max_requests=120, window_seconds=60)
>>>>>>> theirs


@app.get("/health")
def health():
    return {"status": "ok"}
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
=======
=======
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs


app.include_router(auth.router)
app.include_router(targets.router)
app.include_router(scans.router)
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs
