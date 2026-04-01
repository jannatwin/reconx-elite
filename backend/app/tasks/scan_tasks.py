from datetime import datetime, timedelta, timezone
import shlex

from sqlalchemy.orm import Session

from app.core.database import SessionLocal
from app.models.endpoint import Endpoint
from app.models.notification import Notification
from app.models.scan import Scan
from app.models.scan_diff import ScanDiff
from app.models.scan_log import ScanLog
from app.models.scheduled_scan import ScheduledScan
from app.models.subdomain import Subdomain
from app.models.target import Target
from app.models.vulnerability import Vulnerability
from app.services.scan_runner import check_headers, run_gau, run_httpx, run_httpx_enrich, run_nuclei, run_subfinder
from app.services.intelligence import classify_endpoint, auto_tag_endpoint, is_interesting_endpoint, auto_tag_subdomain
from app.services.tool_executor import ToolExecutionResult
from app.tasks.celery_app import celery_app


def _update_scan(scan: Scan, db: Session, **kwargs) -> None:
    for key, value in kwargs.items():
        setattr(scan, key, value)
    db.add(scan)
    db.commit()
    db.refresh(scan)


def _log_step(
    db: Session,
    scan_id: int,
    step: str,
    status: str,
    details: dict,
    result: ToolExecutionResult | None = None,
) -> None:
    if result:
        row = ScanLog(
            scan_id=scan_id,
            step=step,
            status=status,
            started_at=result.started_at,
            ended_at=result.ended_at,
            duration_ms=result.duration_ms,
            attempts=result.attempts,
            stdout=result.stdout,
            stderr=result.stderr,
            details_json=details | result.to_json(),
        )
    else:
        now = datetime.now(timezone.utc)
        row = ScanLog(
            scan_id=scan_id,
            step=step,
            status=status,
            started_at=now,
            ended_at=now,
            duration_ms=0,
            attempts=1,
            stdout="",
            stderr="",
            details_json=details,
        )
    db.add(row)
    db.commit()


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
        scan_config = scan.scan_config_json or {}

        _update_scan(scan, db, status="running", metadata_json={"step": "subfinder", "started": True})

        subdomains, sub_result = run_subfinder(target.domain)
        _log_step(
            db,
            scan.id,
            "subfinder",
            sub_result.status,
            {"count": len(subdomains), "parsed_json": {"subdomains": subdomains}},
            sub_result,
        )
        if sub_result.status != "success":
            _update_scan(scan, db, status="failed", error=sub_result.error, metadata_json={"step": "subfinder"})
            return {"error": sub_result.error}

        for host in subdomains:
            db.add(Subdomain(scan_id=scan.id, hostname=host, is_live=0))
        db.commit()

        _update_scan(scan, db, metadata_json={"step": "httpx"})
        live_hosts, httpx_result = run_httpx(subdomains)
        if httpx_result:
            _log_step(
                db,
                scan.id,
                "httpx",
                httpx_result.status,
                {"count": len(live_hosts), "parsed_json": {"live_hosts": live_hosts}},
                httpx_result,
            )
        if httpx_result and httpx_result.status != "success":
            _update_scan(scan, db, status="failed", error=httpx_result.error, metadata_json={"step": "httpx"})
            return {"error": httpx_result.error}

        live_set = set(live_hosts)
        for row in db.query(Subdomain).filter(Subdomain.scan_id == scan.id).all():
            if row.hostname in live_set:
                row.is_live = 1
        db.commit()

        # Enrich live subdomains
        _update_scan(scan, db, metadata_json={"step": "enrich_subdomains"})
        enrich_data, enrich_result = run_httpx_enrich(live_hosts)
        if enrich_result:
            _log_step(
                db,
                scan.id,
                "enrich_subdomains",
                enrich_result.status,
                {"count": len(enrich_data), "parsed_json": {"enrich_data": enrich_data}},
                enrich_result,
            )
        if enrich_result and enrich_result.status != "success":
            # Don't fail the scan, just log
            pass

        for row in db.query(Subdomain).filter(Subdomain.scan_id == scan.id, Subdomain.is_live == 1).all():
            data = enrich_data.get(row.hostname, {})
            row.ip = data.get("ip")
            row.tech_stack = data.get("tech_stack", [])
            row.cdn_waf = data.get("cdn_waf")
            # Auto-tag subdomains
            tags = auto_tag_subdomain(row.hostname, row.tech_stack)
            # For now, store tags in a separate field if needed, but since subdomain doesn't have tags, maybe add later
        db.commit()

        _update_scan(scan, db, metadata_json={"step": "gau"})
        urls, gau_result = run_gau(target.domain)
        _log_step(
            db,
            scan.id,
            "gau",
            gau_result.status,
            {"count": len(urls), "parsed_json": {"endpoints": urls}},
            gau_result,
        )
        if gau_result.status != "success":
            _update_scan(scan, db, status="failed", error=gau_result.error, metadata_json={"step": "gau"})
            return {"error": gau_result.error}

        deduped_urls = sorted(set(urls))
        for url in deduped_urls:
            category = classify_endpoint(url)
            tags = auto_tag_endpoint(url)
            is_interesting = is_interesting_endpoint(category, tags)
            db.add(Endpoint(scan_id=scan.id, url=url, category=category, tags=tags, is_interesting=is_interesting))
        db.commit()

        _update_scan(scan, db, metadata_json={"step": "nuclei"})
        nuclei_vulns, nuclei_result = run_nuclei(deduped_urls[:300], scan_config)
        if nuclei_result:
            command_preview = " ".join(shlex.quote(part) for part in nuclei_result.command)
            _log_step(
                db,
                scan.id,
                "nuclei",
                nuclei_result.status,
                {
                    "count": len(nuclei_vulns),
                    "scan_config": scan_config,
                    "effective_nuclei_command": command_preview,
                    "effective_nuclei_flags": {
                        "tags": scan_config.get("selected_templates", []),
                        "severity": scan_config.get("severity_filter", []),
                    },
                    "parsed_json": {"vulnerabilities": nuclei_vulns},
                },
                nuclei_result,
            )
        if nuclei_result and nuclei_result.status != "success":
            _update_scan(scan, db, status="failed", error=nuclei_result.error, metadata_json={"step": "nuclei"})
            return {"error": nuclei_result.error}
        for vuln in nuclei_vulns:
            db.add(Vulnerability(scan_id=scan.id, **vuln))

        _update_scan(scan, db, metadata_json={"step": "headers"})
        header_findings, headers_result = check_headers(deduped_urls[:50])
        if headers_result:
            _log_step(
                db,
                scan.id,
                "headers",
                headers_result.status,
                {"count": len(header_findings), "parsed_json": {"header_findings": header_findings}},
                headers_result,
            )
        if headers_result and headers_result.status != "success":
            _update_scan(scan, db, status="failed", error=headers_result.error, metadata_json={"step": "headers"})
            return {"error": headers_result.error}
        for finding in header_findings:
            db.add(Vulnerability(scan_id=scan.id, **finding))
        db.commit()

        # Compute diff with previous scan
        previous_scan = (
            db.query(Scan)
            .filter(Scan.target_id == scan.target_id, Scan.id != scan.id, Scan.status == "completed")
            .order_by(Scan.created_at.desc())
            .first()
        )
        if previous_scan:
            prev_subdomains = {s.hostname for s in previous_scan.subdomains}
            prev_endpoints = {e.url for e in previous_scan.endpoints}
            prev_vulns = {(v.template_id, v.matched_url or "", v.matcher_name or "") for v in previous_scan.vulnerabilities}

            current_subdomains = {s.hostname for s in scan.subdomains}
            current_endpoints = {e.url for e in scan.endpoints}
            current_vulns = {(v.template_id, v.matched_url or "", v.matcher_name or "") for v in scan.vulnerabilities}

            new_subdomains = list(current_subdomains - prev_subdomains)
            new_endpoints = list(current_endpoints - prev_endpoints)
            new_vulns = [
                {"template_id": v.template_id, "severity": v.severity, "matched_url": v.matched_url, "description": v.description}
                for v in scan.vulnerabilities
                if (v.template_id, v.matched_url or "", v.matcher_name or "") not in prev_vulns
            ]

            if new_subdomains or new_endpoints or new_vulns:
                diff = ScanDiff(
                    scan_id=scan.id,
                    previous_scan_id=previous_scan.id,
                    new_subdomains=new_subdomains,
                    new_endpoints=new_endpoints,
                    new_vulnerabilities=new_vulns,
                )
                db.add(diff)
                db.commit()

                # Create notifications
                user = target.owner
                if new_subdomains:
                    db.add(Notification(
                        user_id=user.id,
                        type="new_subdomain",
                        message=f"New subdomains found for {target.domain}: {', '.join(new_subdomains[:5])}{'...' if len(new_subdomains) > 5 else ''}",
                        metadata_json={"target_id": target.id, "scan_id": scan.id, "new_subdomains": new_subdomains}
                    ))
                if new_vulns:
                    db.add(Notification(
                        user_id=user.id,
                        type="new_vulnerability",
                        message=f"New vulnerabilities found for {target.domain}: {len(new_vulns)} new issues",
                        metadata_json={"target_id": target.id, "scan_id": scan.id, "new_vulnerabilities": new_vulns}
                    ))
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


@celery_app.task(name="check_scheduled_scans")
def check_scheduled_scans() -> dict:
    db = SessionLocal()
    try:
        now = datetime.now(timezone.utc)
        due_schedules = db.query(ScheduledScan).filter(
            ScheduledScan.enabled == True,
            ScheduledScan.next_run <= now
        ).all()

        for schedule in due_schedules:
            # Check if there's already a running scan for this target
            running = db.query(Scan).filter(
                Scan.target_id == schedule.target_id,
                Scan.status.in_(["pending", "running"])
            ).first()
            if running:
                continue

            # Create new scan
            scan = Scan(
                target_id=schedule.target_id,
                status="pending",
                metadata_json={"step": "queued", "scheduled": True},
                scan_config_json=schedule.scan_config_json,
            )
            db.add(scan)
            db.commit()
            db.refresh(scan)

            # Trigger scan
            scan_target.delay(scan.id)

            # Update schedule next_run
            if schedule.frequency == "daily":
                schedule.next_run = now.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1)
            elif schedule.frequency == "weekly":
                schedule.next_run = now.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(weeks=1)
            schedule.last_run = now
            db.commit()

        return {"checked": len(due_schedules)}
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc)}
    finally:
        db.close()
