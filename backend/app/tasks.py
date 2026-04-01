from datetime import datetime

from celery.utils.log import get_task_logger

from app.db.session import SessionLocal
from app.models.models import Endpoint, Scan, Subdomain, Target, Vulnerability
from app.services.scanner import basic_security_headers, run_gau, run_httpx, run_nuclei, run_subfinder
from app.worker import celery_app

logger = get_task_logger(__name__)


@celery_app.task(name="app.tasks.run_scan")
def run_scan(scan_id: int, target_id: int):
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id, Scan.target_id == target_id).first()
        target = db.query(Target).filter(Target.id == target_id).first()
        if not scan or not target:
            return

        scan.status = "running"
        scan.started_at = datetime.utcnow()
        db.commit()

        subdomains = sorted(set(run_subfinder(target.domain)))
        live_hosts = run_httpx(subdomains)
        for hostname in subdomains:
            db.add(Subdomain(scan_id=scan.id, hostname=hostname, is_live=hostname in live_hosts))

        urls = sorted(set(run_gau(target.domain)))
        for url in urls:
            db.add(Endpoint(scan_id=scan.id, url=url))

        nuclei_findings = run_nuclei([f"https://{h}" for h in sorted(live_hosts)])
        nuclei_findings.extend(basic_security_headers(sorted(live_hosts)))
        for finding in nuclei_findings:
            info = finding.get("info", {})
            extracted = finding.get("extracted-results") or []
            db.add(
                Vulnerability(
                    scan_id=scan.id,
                    template_id=finding.get("template-id"),
                    severity=info.get("severity"),
                    matched_at=finding.get("matched-at"),
                    description=info.get("name") or (", ".join(extracted) if extracted else None),
                )
            )

        scan.status = "completed"
        scan.completed_at = datetime.utcnow()
        db.commit()
    except Exception as exc:  # noqa: BLE001
        logger.exception("scan failed")
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan:
            scan.status = "failed"
            scan.error_message = str(exc)
            scan.completed_at = datetime.utcnow()
            db.commit()
    finally:
        db.close()
