from sqlalchemy.orm import Session

from app.core.database import SessionLocal
from app.models.endpoint import Endpoint
from app.models.scan import Scan
from app.models.subdomain import Subdomain
from app.models.target import Target
from app.models.vulnerability import Vulnerability
from app.services.scan_runner import check_headers, run_gau, run_httpx, run_nuclei, run_subfinder
from app.tasks.celery_app import celery_app


def _update_scan(scan: Scan, db: Session, **kwargs) -> None:
    for key, value in kwargs.items():
        setattr(scan, key, value)
    db.add(scan)
    db.commit()
    db.refresh(scan)


@celery_app.task(name="scan_target")
def scan_target(scan_id: int) -> dict:
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return {"error": "scan not found"}
        target = db.query(Target).filter(Target.id == scan.target_id).first()
        if not target:
            _update_scan(scan, db, status="failed", error="target not found")
            return {"error": "target not found"}

        _update_scan(scan, db, status="running", metadata_json={"step": "subfinder"})

        subdomains, sub_err = run_subfinder(target.domain)
        if sub_err:
            _update_scan(scan, db, status="failed", error=sub_err)
            return {"error": sub_err}

        for host in sorted(set(subdomains)):
            db.add(Subdomain(scan_id=scan.id, hostname=host, is_live=0))
        db.commit()

        _update_scan(scan, db, metadata_json={"step": "httpx"})
        live_hosts, httpx_err = run_httpx(subdomains)
        if httpx_err:
            _update_scan(scan, db, status="failed", error=httpx_err)
            return {"error": httpx_err}

        for row in db.query(Subdomain).filter(Subdomain.scan_id == scan.id).all():
            if row.hostname in set(live_hosts):
                row.is_live = 1
        db.commit()

        _update_scan(scan, db, metadata_json={"step": "gau"})
        urls, gau_err = run_gau(target.domain)
        if gau_err:
            _update_scan(scan, db, status="failed", error=gau_err)
            return {"error": gau_err}
        for url in sorted(set(urls)):
            db.add(Endpoint(scan_id=scan.id, url=url))
        db.commit()

        _update_scan(scan, db, metadata_json={"step": "nuclei"})
        nuclei_vulns, nuclei_err = run_nuclei(urls[:300])
        if nuclei_err:
            _update_scan(scan, db, status="failed", error=nuclei_err)
            return {"error": nuclei_err}
        for vuln in nuclei_vulns:
            db.add(Vulnerability(scan_id=scan.id, **vuln))

        _update_scan(scan, db, metadata_json={"step": "headers"})
        header_findings = check_headers(urls[:50])
        for finding in header_findings:
            db.add(Vulnerability(scan_id=scan.id, **finding))
        db.commit()

        _update_scan(scan, db, status="completed", metadata_json={"step": "done"})
        return {"status": "completed", "scan_id": scan_id}
    except Exception as exc:  # noqa: BLE001
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan:
            _update_scan(scan, db, status="failed", error=str(exc))
        return {"error": str(exc)}
    finally:
        db.close()
