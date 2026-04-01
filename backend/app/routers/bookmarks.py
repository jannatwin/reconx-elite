from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.deps import get_current_user
from app.models.bookmark import Bookmark
from app.models.endpoint import Endpoint
from app.models.user import User
from app.routers.auth import limiter
from app.schemas.bookmark import BookmarkCreate, BookmarkOut

router = APIRouter(prefix="/bookmarks", tags=["bookmarks"])


@router.post("", response_model=BookmarkOut)
@limiter.limit("120/minute")
def create_bookmark(
    payload: BookmarkCreate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    # Check if endpoint exists and user has access
    endpoint = db.query(Endpoint).join(Endpoint.scan).join(Endpoint.scan.target).filter(
        Endpoint.id == payload.endpoint_id,
        Endpoint.scan.target.owner_id == user.id
    ).first()
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
    return bookmark


@router.get("", response_model=list[BookmarkOut])
@limiter.limit("120/minute")
def list_bookmarks(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    return (
        db.query(Bookmark)
        .filter(Bookmark.user_id == user.id)
        .all()
    )


@router.delete("/{bookmark_id}")
@limiter.limit("120/minute")
def delete_bookmark(
    bookmark_id: int,
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
    return {"message": "Bookmark deleted"}