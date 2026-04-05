"""Persist modular pipeline outputs."""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.models.scan_artifact import ScanArtifact

_PREVIEW_LIMIT = 65_000


def persist_scan_artifact(
    db: Session,
    *,
    scan_id: int,
    module: str,
    tool: str,
    summary_json: dict | None = None,
    text_preview: str | None = None,
    blob_path: str | None = None,
    format_: str = "text",
) -> ScanArtifact:
    preview = text_preview
    if preview and len(preview) > _PREVIEW_LIMIT:
        preview = preview[:_PREVIEW_LIMIT] + "\n... [truncated]"
    row = ScanArtifact(
        scan_id=scan_id,
        module=module,
        tool=tool,
        format_=format_,
        summary_json=summary_json or {},
        text_preview=preview,
        blob_path=blob_path,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row
