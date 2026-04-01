from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_db
from app.core.deps import get_current_user
from app.models.bookmark import Bookmark
from app.models.endpoint import Endpoint
from app.models.scan import Scan
from app.models.target import Target
from app.models.user import User
from app.routers.auth import limiter
from app.schemas.bookmark import BookmarkCreate, BookmarkOut
from app.services.audit import log_audit_event

router = APIRouter(prefix="/bookmarks", tags=["bookmarks"])


@router.post("", response_model=BookmarkOut)
@limiter.limit(settings.write_rate_limit)
def create_bookmark(
    payload: BookmarkCreate,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    endpoint = (
        db.query(Endpoint)
        .join(Scan, Scan.id == Endpoint.scan_id)
        .join(Target, Target.id == Scan.target_id)
        .filter(Endpoint.id == payload.endpoint_id, Target.owner_id == user.id)
        .first()
    )
    if not endpoint:
        raise HTTPException(status_code=404, detail="Endpoint not found")

    existing = db.query(Bookmark).filter(
        Bookmark.user_id == user.id,
        Bookmark.endpoint_id == payload.endpoint_id
    ).first()
    if existing:
        raise HTTPException(status_code=400, detail="Already bookmarked")

    bookmark = Bookmark(
        user_id=user.id,
        endpoint_id=payload.endpoint_id,
        note=payload.note,
    )
    db.add(bookmark)
    db.commit()
    db.refresh(bookmark)
    log_audit_event(
        db,
        action="bookmark_created",
        user_id=user.id,
        ip_address=request.client.host if request.client else None,
        metadata_json={"bookmark_id": bookmark.id, "endpoint_id": bookmark.endpoint_id},
    )
    return bookmark


@router.get("", response_model=list[BookmarkOut])
@limiter.limit(settings.read_rate_limit)
def list_bookmarks(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    return (
        db.query(Bookmark)
        .filter(Bookmark.user_id == user.id)
        .all()
    )


@router.delete("/{bookmark_id}")
@limiter.limit(settings.write_rate_limit)
def delete_bookmark(
    bookmark_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    bookmark = db.query(Bookmark).filter(
        Bookmark.id == bookmark_id,
        Bookmark.user_id == user.id
    ).first()
    if not bookmark:
        raise HTTPException(status_code=404, detail="Bookmark not found")

    db.delete(bookmark)
    db.commit()
    log_audit_event(
        db,
        action="bookmark_deleted",
        user_id=user.id,
        ip_address=request.client.host if request.client else None,
        metadata_json={"bookmark_id": bookmark_id},
    )
    return {"message": "Bookmark deleted"}
