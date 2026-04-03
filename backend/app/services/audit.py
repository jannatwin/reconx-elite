from sqlalchemy.orm import Session

from app.models.audit_log import AuditLog


def log_audit_event(
    db: Session,
    *,
    action: str,
    user_id: int | None = None,
    ip_address: str | None = None,
    metadata_json: dict | None = None,
) -> None:
    db.add(
        AuditLog(
            action=action,
            user_id=user_id,
            ip_address=ip_address,
            metadata_json=metadata_json or {},
        )
    )
