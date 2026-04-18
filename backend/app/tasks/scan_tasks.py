from __future__ import annotations

import asyncio
import logging
import shlex
from datetime import datetime, timedelta, timezone

from celery import chain
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload

from app.core.config import settings
from app.core.database import get_sessionmaker
from app.models.ai_report import AIReport
from app.models.attack_path import AttackPath
from app.models.blind_xss_hit import BlindXssHit
from app.models.endpoint import Endpoint
from app.models.javascript_asset import JavaScriptAsset
from app.models.notification import Notification
from app.models.payload_opportunity import PayloadOpportunity
from app.models.scan import Scan
from app.models.scan_diff import ScanDiff
from app.models.scan_log import ScanLog
from app.models.scheduled_scan import ScheduledScan
from app.models.subdomain import Subdomain
from app.models.ssrf_signal import SsrfSignal
from app.models.target import Target
from app.models.vulnerability import Vulnerability
from app.services.intelligence_learning import learning_service
from app.services.intelligence import (
    analyze_javascript_assets,
    build_subdomain_record,
    filter_nuclei_targets,
    normalize_and_dedupe_urls,
    normalize_endpoint_url,
    rank_attack_paths,
    select_javascript_assets,
    synthesize_heuristic_findings,
)
from app.services.ai_service import (
    analyze_scan_data,
    analyze_live_hosts,
    analyze_subdomains,
    analyze_javascript_endpoints,
    analyze_nuclei_findings,
    build_javascript_asset_summaries_for_ai,
    generate_elite_vulnerability_report,
    estimate_bounty_potential,
    _should_generate_report,
)
from app.services.websocket import (
    notify_scan_completed,
    notify_scan_failed,
    notify_critical_vulnerability,
    notify_scan_started,
)
from app.services.external_notifications import notification_service
from app.services.blind_xss_service import BlindXssService
from app.services.payload_generator import PayloadGenerator
from app.services.payload_tester import OpportunityDetector
from app.services.passive_dns import fetch_crtsh_subdomains, run_github_subdomains_cli
from app.services.scan_artifact_service import persist_scan_artifact
from app.services.scan_pipeline import (
    pipeline_stage_total,
    resolve_pipeline_stages,
    stage_index_and_total,
)
from app.services.scan_runner import (
    check_headers,
    run_dalfox_url,
    run_ffuf_dirs,
    run_ffuf_dns,
    run_gau,
    run_gowitness_screenshots,
    run_httpx,
    run_httpx_enrich,
    run_katana,
    run_masscan_hosts,
    run_nmap_ports,
    run_nuclei,
    run_sqlmap_batch,
    run_subfinder,
    run_wafw00f_sample,
    run_waybackurls,
)
from app.services.ssrf_service import SsrfService
from app.services.tool_executor import ToolExecutionResult
from app.tasks.celery_app import celery_app
from app.schemas.scan_modules import parse_modules_from_config

logger = logging.getLogger(__name__)


def _emit_agent_log_event(message: dict) -> None:
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return
    try:
        from app.services.websocket import publish_agent_log_event

        loop.create_task(publish_agent_log_event(message))
    except Exception:
        logger.debug("agent log publish unavailable", exc_info=True)


def _nuclei_targets_from_scan_endpoints(db: Session, scan_id: int) -> list[str]:
    rows = db.query(Endpoint).filter(Endpoint.scan_id == scan_id).all()
    records: list[dict] = []
    for row in rows:
        rec = normalize_endpoint_url(
            row.url, source=row.source or "gau", js_source=row.js_source
        )
        if rec:
            records.append(rec)
    return filter_nuclei_targets(records)


def _default_metadata(
    stage: str = "queued", stage_index: int = 0, stage_total: int | None = None
) -> dict:
    total = stage_total if stage_total is not None else 4
    return {
        "stage": stage,
        "stage_index": stage_index,
        "stage_total": total,
        "progress_percent": (
            int((stage_index / total) * 100) if total and stage_index else 0
        ),
        "warnings": [],
        "errors": [],
    }


async def _load_scan(scan_id: int, db: Session) -> tuple[Scan | None, Target | None]:
    scan = (
        db.query(Scan)
        .options(
            selectinload(Scan.target),
            selectinload(Scan.logs),
            selectinload(Scan.diffs),
        )
        .filter(Scan.id == scan_id)
        .first()
    )
    if not scan:
        return None, None

    # Send WebSocket notification when scan starts
    if scan.status == "pending":
        await notify_scan_started(scan.target.owner_id, scan.target.domain, scan.id)

    return scan, scan.target


def _merge_metadata(scan: Scan, **updates) -> dict:
    metadata = _default_metadata()
    metadata.update(scan.metadata_json or {})
    metadata.setdefault("warnings", [])
    metadata.setdefault("errors", [])
    metadata.update(updates)
    return metadata


def _update_scan(scan: Scan, db: Session, **kwargs) -> None:
    for key, value in kwargs.items():
        setattr(scan, key, value)
    db.add(scan)
    db.commit()
    db.refresh(scan)


def _set_stage(scan: Scan, db: Session, stage_name: str) -> None:
    stage_index, stage_total = stage_index_and_total(scan.metadata_json, stage_name)
    metadata = _merge_metadata(
        scan,
        stage=stage_name,
        stage_index=stage_index,
        stage_total=stage_total,
        progress_percent=(
            int(((stage_index - 1) / stage_total) * 100) if stage_total else 0
        ),
    )
    logger.info(
        "scan_stage scan_id=%s stage=%s stage_index=%s stage_total=%s progress_percent=%s",
        scan.id,
        stage_name,
        stage_index,
        stage_total,
        metadata.get("progress_percent"),
    )
    _emit_agent_log_event(
        {
            "event": "scan_phase_transition",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "scan_id": scan.id,
            "target_id": scan.target_id,
            "task": stage_name,
            "status": "active",
            "success": True,
            "message": f"Entered scan phase: {stage_name}",
        }
    )
    _update_scan(scan, db, status="running", metadata_json=metadata)


def _append_warning(scan: Scan, db: Session, message: str) -> None:
    metadata = _merge_metadata(scan)
    warnings = list(metadata.get("warnings") or [])
    warnings.append(message)
    metadata["warnings"] = warnings[-20:]
    _emit_agent_log_event(
        {
            "event": "scan_warning",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "scan_id": scan.id,
            "target_id": scan.target_id,
            "task": metadata.get("stage"),
            "status": "warning",
            "success": False,
            "message": message,
        }
    )
    _update_scan(scan, db, metadata_json=metadata)


def _append_error(scan: Scan, db: Session, message: str) -> None:
    metadata = _merge_metadata(scan)
    errors = list(metadata.get("errors") or [])
    errors.append(message)
    metadata["errors"] = errors[-20:]
    _update_scan(scan, db, error=message, metadata_json=metadata)


def _log_step(
    db: Session,
    scan_id: int,
    step: str,
    status: str,
    details: dict,
    result: ToolExecutionResult | None = None,
) -> None:
    if result:
        logger.info(
            "scan_step scan_id=%s step=%s status=%s duration_ms=%s attempts=%s",
            scan_id,
            step,
            status,
            result.duration_ms,
            result.attempts,
        )
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


def _fail_scan(scan: Scan, db: Session, *, stage: str, message: str) -> None:
    _append_error(scan, db, message)
    metadata = _merge_metadata(
        scan,
        stage=stage,
        progress_percent=min(
            int((scan.metadata_json or {}).get("progress_percent", 0)), 99
        ),
    )
    _emit_agent_log_event(
        {
            "event": "scan_hard_stop",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "scan_id": scan.id,
            "target_id": scan.target_id,
            "task": stage,
            "status": "failed",
            "success": False,
            "message": message,
        }
    )
    _update_scan(scan, db, status="failed", error=message, metadata_json=metadata)


def _soft_log(
    scan: Scan, db: Session, step: str, payload: dict, warning: str | None = None
) -> None:
    if warning:
        _append_warning(scan, db, f"{step}: {warning}")
    _log_step(db, scan.id, step, "warning" if warning else "success", payload)


def _upsert_endpoints(db: Session, scan_id: int, records: list[dict]) -> None:
    existing = {
        row.normalized_url: row
        for row in db.query(Endpoint).filter(Endpoint.scan_id == scan_id).all()
    }
    for record in records:
        normalized_url = record.get("normalized_url")
        if not normalized_url:
            continue
        row = existing.get(normalized_url)
        if row:
            row.priority_score = max(
                row.priority_score, record.get("priority_score", 0)
            )
            row.focus_reasons = sorted(
                set(row.focus_reasons or []) | set(record.get("focus_reasons") or [])
            )
            row.tags = sorted(set(row.tags or []) | set(record.get("tags") or []))
            row.is_interesting = row.is_interesting or bool(
                record.get("is_interesting")
            )
            row.category = (
                row.category
                if row.category != "general"
                else (record.get("category") or row.category)
            )
            if row.source == "gau" and record.get("source") == "js":
                row.js_source = record.get("js_source") or row.js_source
            elif row.source == "js" and record.get("source") == "gau":
                row.source = "gau"
        else:
            db.add(
                Endpoint(
                    scan_id=scan_id,
                    **{k: v for k, v in record.items() if not k.startswith("is_")},
                )
            )
    db.commit()


def _create_js_assets(db: Session, scan_id: int, asset_rows: list[dict]) -> None:
    for row in asset_rows:
        db.add(JavaScriptAsset(scan_id=scan_id, **row))
    db.commit()


def _create_vulnerabilities(
    db: Session, scan_id: int, vulnerabilities: list[dict]
) -> None:
    existing = {
        (row.template_id, row.matched_url or "", row.matcher_name or "")
        for row in db.query(Vulnerability)
        .filter(Vulnerability.scan_id == scan_id)
        .all()
    }

    # Get scan for user ID
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    user_id = scan.target.owner_id if scan else None

    created_vulns = []
    for vulnerability in vulnerabilities:
        key = (
            vulnerability["template_id"],
            vulnerability.get("matched_url") or "",
            vulnerability.get("matcher_name") or "",
        )
        if key in existing:
            continue
        existing.add(key)

        # Create vulnerability object
        vuln_obj = Vulnerability(scan_id=scan_id, **vulnerability)
        db.add(vuln_obj)
        created_vulns.append(vuln_obj)

    db.commit()

    # Trigger learning for new vulnerabilities
    if user_id and created_vulns:
        for vuln in created_vulns:
            try:
                # Async learning will be handled in background
                # For now, we'll queue it as a background task
                from app.tasks.learning_tasks import learn_from_vulnerability_task

                learn_from_vulnerability_task.delay(user_id, vuln.id)
            except Exception as e:
                logger.warning(
                    f"Failed to queue learning for vulnerability {vuln.id}: {e}"
                )


def _create_attack_paths(db: Session, scan_id: int, attack_paths: list[dict]) -> None:
    for attack_path in attack_paths:
        db.add(AttackPath(scan_id=scan_id, **attack_path))
    db.commit()


def _detect_payload_opportunities(db: Session, scan_id: int) -> None:
    """Detect and store payload testing opportunities for endpoints in this scan."""
    scan = (
        db.query(Scan)
        .options(selectinload(Scan.target))
        .filter(Scan.id == scan_id)
        .first()
    )
    if not scan or not scan.target:
        return
    target = scan.target
    endpoints = db.query(Endpoint).filter(Endpoint.scan_id == scan_id).all()
    detector = OpportunityDetector()

    for endpoint in endpoints:
        # Extract parameters from URL (simple approach: from query string)
        parameters = _extract_parameters(endpoint.normalized_url)
        if not parameters:
            continue

        # Detect opportunities
        opportunities = detector.detect_opportunities(endpoint.url, parameters)

        for opp in opportunities:
            # Check if this opportunity already exists
            existing = (
                db.query(PayloadOpportunity)
                .filter(
                    PayloadOpportunity.endpoint_id == endpoint.id,
                    PayloadOpportunity.parameter_name == opp["parameter_name"],
                    PayloadOpportunity.vulnerability_type.in_(
                        opp["vulnerability_types"]
                    ),
                )
                .first()
            )

            if existing:
                continue

            for vuln_type in opp["vulnerability_types"]:
                payloads = PayloadGenerator.get_payloads_for_type(vuln_type)

                # For blind XSS, generate payloads with tokens
                if vuln_type == "blind_xss":
                    # Get user ID from target owner
                    user_id = target.owner_id
                    token = BlindXssService.create_token_for_opportunity(
                        db, user_id, None
                    )  # Will be updated with opp ID after creation

                    # Replace __TOKEN__ placeholder with actual token and domain
                    domain = target.domain  # Use target domain as base
                    modified_payloads = []
                    for payload in payloads[:3]:  # Only use first 3 blind XSS payloads
                        modified_payload = BlindXssService.create_payload_with_token(
                            payload, token, domain
                        )
                        modified_payloads.append(modified_payload)

                    payloads = modified_payloads

                # For SSRF, generate payloads with tokens
                elif vuln_type == "ssrf":
                    # Get user ID from target owner
                    user_id = target.owner_id
                    token = SsrfService.create_token_for_opportunity(
                        db, user_id, None
                    )  # Will be updated with opp ID after creation

                    # Replace __TOKEN__ placeholder with actual token and domain
                    domain = settings.backend_callback_url.split("://")[
                        -1
                    ]  # Use callback backend URL
                    modified_payloads = []
                    for payload in payloads[:5]:  # Use first 5 SSRF payloads
                        modified_payload = SsrfService.create_payload_with_token(
                            payload, token, domain
                        )
                        modified_payloads.append(modified_payload)

                    payloads = modified_payloads

                db_opp = PayloadOpportunity(
                    endpoint_id=endpoint.id,
                    scan_id=scan_id,
                    parameter_name=opp["parameter_name"],
                    parameter_location=opp["parameter_location"],
                    vulnerability_type=vuln_type,
                    confidence=opp["confidence"],
                    payloads_json=payloads[:5],  # Store first 5 payloads
                    notes=opp["reason"],
                )
                db.add(db_opp)
                db.flush()  # Get the ID

                # For blind XSS, update the token with the opportunity ID
                if vuln_type == "blind_xss":
                    # Find the token entry and update it
                    token_entry = (
                        db.query(BlindXssHit)
                        .filter(
                            BlindXssHit.user_id == target.owner_id,
                            BlindXssHit.payload_opportunity_id.is_(None),
                        )
                        .order_by(BlindXssHit.triggered_at.desc())
                        .first()
                    )

                    if token_entry:
                        token_entry.payload_opportunity_id = db_opp.id

                # For SSRF, update the token with the opportunity ID
                elif vuln_type == "ssrf":
                    # Find the token entry and update it
                    token_entry = (
                        db.query(SsrfSignal)
                        .filter(
                            SsrfSignal.user_id == target.owner_id,
                            SsrfSignal.payload_opportunity_id.is_(None),
                        )
                        .order_by(SsrfSignal.triggered_at.desc())
                        .first()
                    )

                    if token_entry:
                        token_entry.payload_opportunity_id = db_opp.id

    db.commit()


def _extract_parameters(url: str) -> list[str]:
    """Extract parameter names from URL query string."""
    from urllib.parse import parse_qs, urlparse

    try:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        return list(params.keys())
    except Exception:
        return []


async def _generate_ai_reports(
    db: Session, scan: Scan, all_vulnerabilities: list[dict]
) -> None:
    """Generate AI-powered elite reports for high/critical vulnerabilities.

    Args:
        db: Database session
        scan: Scan object
        all_vulnerabilities: Combined list of nuclei and heuristic findings
    """
    # Check if AI processing is enabled for this target
    if not scan.target.enable_ai_processing:
        logger.info(f"AI processing disabled for target {scan.target.domain}")
        return

    # Filter for high/critical vulnerabilities
    high_critical_vulns = [
        vuln
        for vuln in all_vulnerabilities
        if vuln.get("severity") in ["high", "critical"]
    ]

    if not high_critical_vulns:
        return

    # Count existing AI reports for this scan
    existing_reports = (
        db.query(AIReport)
        .join(Vulnerability)
        .filter(Vulnerability.scan_id == scan.id)
        .count()
    )

    reports_generated = 0
    for vuln in high_critical_vulns[:5]:  # Limit to top 5 to manage API usage
        # Check safety controls
        if not _should_generate_report(
            vuln.get("severity", ""), existing_reports + reports_generated
        ):
            continue

        try:
            # Generate elite professional report
            report_data = await generate_elite_vulnerability_report(vuln)

            if "error" in report_data:
                logger.warning(f"Failed to generate AI report: {report_data['error']}")
                continue

            # Find the corresponding vulnerability in the database
            db_vuln = (
                db.query(Vulnerability)
                .filter(
                    Vulnerability.scan_id == scan.id,
                    Vulnerability.template_id == vuln.get("template_id"),
                    Vulnerability.matched_url == vuln.get("matched_url"),
                )
                .first()
            )

            if not db_vuln:
                logger.warning(f"Could not find matching vulnerability for report")
                continue

            # Create AI report record
            ai_report = AIReport(
                vulnerability_id=db_vuln.id,
                title=report_data.get(
                    "title",
                    f"{vuln.get('template_id', 'Unknown')} on {vuln.get('matched_url', 'N/A')}",
                ),
                summary=report_data.get("summary", ""),
                severity=report_data.get("severity", vuln.get("severity", "unknown")),
                confidence_score=report_data.get("confidence_score", "medium"),
                cwe_mapping=report_data.get("cwe_mapping", "[]"),
                owasp_mapping=report_data.get("owasp_mapping", "[]"),
                cvss_score=report_data.get("cvss_score", "0.0"),
                technical_details=report_data.get("technical_details", ""),
                proof_of_concept=report_data.get("proof_of_concept", ""),
                exploit_draft=report_data.get("exploit_draft", ""),
                business_impact=report_data.get("business_impact", ""),
                bounty_estimate=report_data.get("bounty_estimate", "$0-$0"),
                remediation_steps=report_data.get("remediation_steps", ""),
                ai_model_version=report_data.get("ai_model_version", "gemini-1.5-pro"),
                processing_time_ms=report_data.get("processing_time_ms", 0),
                data_sent_hash=report_data.get("data_sent_hash", ""),
                is_ai_assisted=report_data.get("is_ai_assisted", True),
            )

            db.add(ai_report)
            db.commit()

            # Log successful report generation
            _soft_log(
                scan,
                db,
                "ai_report_generated",
                {
                    "vulnerability_id": db_vuln.id,
                    "template_id": vuln.get("template_id"),
                    "severity": vuln.get("severity"),
                    "url": vuln.get("matched_url"),
                    "report_id": ai_report.id,
                    "confidence_score": report_data.get("confidence_score"),
                    "processing_time_ms": report_data.get("processing_time_ms"),
                },
            )

            reports_generated += 1

            # Send notification for critical findings
            if vuln.get("severity") in ["high", "critical"]:
                vuln_payload = {
                    "id": db_vuln.id,
                    "template_id": vuln.get("template_id"),
                    "severity": vuln.get("severity"),
                    "matched_url": vuln.get("matched_url"),
                    "description": report_data.get("summary", ""),
                }

                # Internal websocket notification
                if vuln.get("severity") == "critical":
                    await notify_critical_vulnerability(
                        scan.target.owner_id, vuln_payload
                    )

                # External notifications (Slack/Discord)
                await notification_service.notify_critical_finding(vuln_payload)

        except Exception as e:
            logger.exception("Error generating AI report")
            _soft_log(
                scan,
                db,
                "ai_report_generation_failed",
                {"error": str(e)[:200], "template_id": vuln.get("template_id")},
                warning="AI report generation failed",
            )

    if reports_generated > 0:
        logger.info(f"Generated {reports_generated} AI reports for scan {scan.id}")
        _soft_log(
            scan,
            db,
            "ai_report_generation",
            {
                "reports_generated": reports_generated,
                "total_high_critical": len(high_critical_vulns),
                "note": "Professional reports stored in database",
            },
        )


def _compute_diff_and_notifications(db: Session, scan: Scan, target: Target) -> None:
    previous_scan = (
        db.query(Scan)
        .options(
            selectinload(Scan.subdomains),
            selectinload(Scan.endpoints),
            selectinload(Scan.vulnerabilities),
        )
        .filter(
            Scan.target_id == scan.target_id,
            Scan.id != scan.id,
            Scan.status == "completed",
        )
        .order_by(Scan.created_at.desc())
        .first()
    )
    if not previous_scan:
        return

    current_subdomains = {row.hostname for row in scan.subdomains}
    current_endpoints = {row.normalized_url for row in scan.endpoints}
    current_vulns = {
        (row.template_id, row.matched_url or "", row.matcher_name or "")
        for row in scan.vulnerabilities
    }

    prev_subdomains = {row.hostname for row in previous_scan.subdomains}
    prev_endpoints = {row.normalized_url for row in previous_scan.endpoints}
    prev_vulns = {
        (row.template_id, row.matched_url or "", row.matcher_name or "")
        for row in previous_scan.vulnerabilities
    }

    new_subdomains = sorted(current_subdomains - prev_subdomains)
    new_endpoints = sorted(current_endpoints - prev_endpoints)
    new_vulns = [
        {
            "id": row.id,
            "template_id": row.template_id,
            "severity": row.severity,
            "matched_url": row.matched_url,
            "description": row.description,
            "source": row.source,
        }
        for row in scan.vulnerabilities
        if (row.template_id, row.matched_url or "", row.matcher_name or "")
        not in prev_vulns
    ]
    if not new_subdomains and not new_endpoints and not new_vulns:
        return

    db.add(
        ScanDiff(
            scan_id=scan.id,
            previous_scan_id=previous_scan.id,
            new_subdomains=new_subdomains,
            new_endpoints=new_endpoints,
            new_vulnerabilities=new_vulns,
        )
    )
    db.commit()

    if new_subdomains:
        db.add(
            Notification(
                user_id=target.owner_id,
                type="new_subdomain",
                message=f"New subdomains found for {target.domain}: {', '.join(new_subdomains[:5])}",
                metadata_json={
                    "target_id": target.id,
                    "scan_id": scan.id,
                    "new_subdomains": new_subdomains,
                },
            )
        )
    if new_vulns:
        db.add(
            Notification(
                user_id=target.owner_id,
                type="new_vulnerability",
                message=f"New vulnerabilities found for {target.domain}: {len(new_vulns)} new issue(s)",
                metadata_json={
                    "target_id": target.id,
                    "scan_id": scan.id,
                    "new_vulnerabilities": new_vulns,
                },
            )
        )
    db.commit()


@celery_app.task(name="app.tasks.scan_tasks.scan_stage_passive_dns")
def scan_stage_passive_dns(scan_id: int) -> dict:
    return asyncio.run(_scan_stage_passive_dns_async(scan_id))


async def _scan_stage_passive_dns_async(scan_id: int) -> dict:
    db = get_sessionmaker()()
    try:
        scan, target = await _load_scan(scan_id, db)
        if not scan or not target:
            return {"scan_id": scan_id, "passive_subdomains": []}
        _set_stage(scan, db, "passive_dns")
        mods = parse_modules_from_config(scan.scan_config_json or {})
        hosts: list[str] = []
        if mods.passive_dns.crtsh_enabled:
            hosts.extend(fetch_crtsh_subdomains(target.domain))
        if mods.passive_dns.github_subdomains_enabled:
            hosts.extend(run_github_subdomains_cli(target.domain))
        seen: dict[str, str] = {}
        for h in hosts:
            k = h.lower().rstrip(".")
            seen.setdefault(k, h)
        merged = list(seen.values())
        _log_step(
            db,
            scan.id,
            "passive_dns",
            "success",
            {"count": len(merged), "parsed_json": {"passive_subdomains": merged[:200]}},
        )
        return {"scan_id": scan.id, "passive_subdomains": merged}
    finally:
        db.close()


@celery_app.task(name="app.tasks.scan_tasks.scan_stage_subfinder")
def scan_stage_subfinder(payload: int | dict) -> dict:
    return asyncio.run(_scan_stage_subfinder_async(payload))


async def _scan_stage_subfinder_async(payload: int | dict) -> dict:
    if isinstance(payload, int):
        scan_id = payload
        passive_subdomains: list[str] = []
    else:
        scan_id = int(payload.get("scan_id") or 0)
        passive_subdomains = list(payload.get("passive_subdomains") or [])
    db = get_sessionmaker()()
    try:
        scan, target = await _load_scan(scan_id, db)
        if not scan or not target:
            return {"scan_id": scan_id, "subdomains": []}
        _set_stage(scan, db, "subfinder")
        subdomains, result = run_subfinder(target.domain)
        _log_step(
            db,
            scan.id,
            "subfinder",
            result.status,
            {"count": len(subdomains), "parsed_json": {"subdomains": subdomains}},
            result,
        )
        if result.status != "success":
            _fail_scan(
                scan, db, stage="subfinder", message=result.error or "subfinder failed"
            )
            raise RuntimeError(result.error or "subfinder failed")

        merged_map: dict[str, str] = {}
        for host in passive_subdomains + subdomains:
            k = (host or "").lower().rstrip(".")
            if k:
                merged_map.setdefault(k, host.lower().rstrip("."))
        final_hosts = list(merged_map.values())

        for host in final_hosts:
            db.add(Subdomain(scan_id=scan.id, hostname=host))
        db.commit()

        # AI-powered subdomain analysis for high-value targets
        try:
            ai_analysis = await analyze_subdomains(final_hosts)
            if ai_analysis and "high_value_targets" in ai_analysis:
                _soft_log(
                    scan,
                    db,
                    "ai_subdomain_analysis",
                    {
                        "high_value_count": len(
                            ai_analysis.get("high_value_targets", [])
                        ),
                        "potential_leaks": len(ai_analysis.get("potential_leaks", [])),
                        "suggested_templates": ai_analysis.get(
                            "suggested_nuclei_templates", []
                        ),
                        "total_processed": ai_analysis.get("total_processed", 0),
                        "batches_processed": ai_analysis.get("batches_processed", 0),
                    },
                )
                # Store AI insights in scan metadata for later use
                metadata = _merge_metadata(scan)
                metadata["ai_subdomain_analysis"] = ai_analysis
                _update_scan(scan, db, metadata_json=metadata)
        except Exception as e:
            _soft_log(
                scan,
                db,
                "ai_subdomain_analysis",
                {"error": str(e)[:200]},
                warning="AI subdomain analysis failed",
            )

        return {"scan_id": scan.id, "subdomains": final_hosts}
    finally:
        db.close()


@celery_app.task(name="app.tasks.scan_tasks.scan_stage_active_dns")
def scan_stage_active_dns(payload: dict) -> dict:
    return asyncio.run(_scan_stage_active_dns_async(payload))


async def _scan_stage_active_dns_async(payload: dict) -> dict:
    if not isinstance(payload, dict):
        raise ValueError("Invalid payload")
    scan_id = payload.get("scan_id")
    if not scan_id or not isinstance(scan_id, int):
        raise ValueError("Invalid scan_id")
    db = get_sessionmaker()()
    try:
        scan, target = await _load_scan(scan_id, db)
        if not scan or not target:
            return payload
        _set_stage(scan, db, "active_dns")
        mods = parse_modules_from_config(scan.scan_config_json or {})
        wl = mods.active_dns.wordlist_path or ""
        if not wl and settings.seclists_base_path:
            wl = f"{settings.seclists_base_path}/Discovery/DNS/subdomains-top1million-110000.txt"
        max_l = min(
            mods.active_dns.max_fuzz_labels, settings.scan_active_dns_max_labels
        )
        extra, ff_res = run_ffuf_dns(target.domain, wl, max_l)
        if ff_res:
            _log_step(
                db,
                scan.id,
                "active_dns",
                ff_res.status,
                {"count": len(extra), "parsed_json": {"hosts": extra[:100]}},
                ff_res,
            )
        existing = {
            r.hostname.lower()
            for r in db.query(Subdomain).filter(Subdomain.scan_id == scan.id).all()
        }
        added = 0
        for h in extra:
            k = h.lower().rstrip(".")
            if k and k not in existing:
                existing.add(k)
                db.add(Subdomain(scan_id=scan.id, hostname=k))
                added += 1
        db.commit()
        base_subs = list(payload.get("subdomains") or [])
        merged = list(dict.fromkeys([s.lower().rstrip(".") for s in base_subs + extra]))
        return payload | {"subdomains": merged}
    finally:
        db.close()


@celery_app.task(name="app.tasks.scan_tasks.scan_stage_httpx")
def scan_stage_httpx(payload: dict) -> dict:
    return asyncio.run(_scan_stage_httpx_async(payload))


async def _scan_stage_httpx_async(payload: dict) -> dict:
    # Validate payload structure
    if not isinstance(payload, dict):
        raise ValueError("Invalid payload: expected dictionary")

    scan_id = payload.get("scan_id")
    if not scan_id or not isinstance(scan_id, int):
        raise ValueError("Invalid or missing scan_id in payload")

    db = get_sessionmaker()()
    try:
        scan, target = await _load_scan(scan_id, db)
        if not scan or not target:
            return payload
        _set_stage(scan, db, "httpx")

        subdomains = payload.get("subdomains") or [
            row.hostname for row in scan.subdomains
        ]
        if not subdomains:
            _soft_log(
                scan,
                db,
                "httpx",
                {"error": "No subdomains to test"},
                warning="No subdomains available",
            )
            return payload

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
            _fail_scan(
                scan, db, stage="httpx", message=httpx_result.error or "httpx failed"
            )
            raise RuntimeError(httpx_result.error or "httpx failed")

        enrich_data, enrich_result = run_httpx_enrich(live_hosts)
        if enrich_result:
            _log_step(
                db,
                scan.id,
                "enrichment",
                enrich_result.status,
                {"count": len(enrich_data), "parsed_json": enrich_data},
                enrich_result,
            )
            if enrich_result.status != "success":
                _append_warning(
                    scan, db, enrich_result.error or "subdomain enrichment failed"
                )
        else:
            _soft_log(scan, db, "enrichment", {"count": 0, "parsed_json": {}})

        live_set = set(live_hosts)
        subdomain_rows = db.query(Subdomain).filter(Subdomain.scan_id == scan.id).all()
        for row in subdomain_rows:
            record = build_subdomain_record(row.hostname, enrich_data, live_set)
            row.is_live = record["is_live"]
            row.environment = record["environment"]
            row.tags = record["tags"]
            row.takeover_candidate = record["takeover_candidate"]
            row.cname = record["cname"]
            row.ip = record["ip"]
            row.tech_stack = record["tech_stack"]
            row.cdn = record["cdn"]
            row.waf = record["waf"]
            row.cdn_waf = record["cdn_waf"]
        db.commit()

        # AI-powered live host analysis
        try:
            if live_hosts:
                httpx_output = "\n".join(live_hosts)
                ai_analysis = await analyze_live_hosts(httpx_output)
                if ai_analysis and "high_value_targets" in ai_analysis:
                    _soft_log(
                        scan,
                        db,
                        "ai_live_host_analysis",
                        {
                            "high_value_count": len(
                                ai_analysis.get("high_value_targets", [])
                            ),
                            "potential_leaks": len(
                                ai_analysis.get("potential_leaks", [])
                            ),
                            "suggested_templates": ai_analysis.get(
                                "suggested_nuclei_templates", []
                            ),
                        },
                    )
                    # Store AI insights in scan metadata
                    metadata = _merge_metadata(scan)
                    metadata["ai_live_host_analysis"] = ai_analysis
                    _update_scan(scan, db, metadata_json=metadata)
        except Exception as e:
            _soft_log(
                scan,
                db,
                "ai_live_host_analysis",
                {"error": str(e)[:200]},
                warning="AI live host analysis failed",
            )

        return payload | {"live_hosts": live_hosts}
    finally:
        db.close()


@celery_app.task(name="app.tasks.scan_tasks.scan_stage_port_scan")
def scan_stage_port_scan(payload: dict) -> dict:
    return asyncio.run(_scan_stage_port_scan_async(payload))


async def _scan_stage_port_scan_async(payload: dict) -> dict:
    if not isinstance(payload, dict):
        raise ValueError("Invalid payload")
    scan_id = payload.get("scan_id")
    if not scan_id or not isinstance(scan_id, int):
        raise ValueError("Invalid scan_id")
    db = get_sessionmaker()()
    try:
        scan, target = await _load_scan(scan_id, db)
        if not scan or not target:
            return payload
        _set_stage(scan, db, "port_scan")
        mods = parse_modules_from_config(scan.scan_config_json or {})
        live = payload.get("live_hosts") or []
        hosts = []
        for line in live:
            if isinstance(line, str) and line.startswith("http"):
                from urllib.parse import urlparse

                h = urlparse(line).hostname
                if h:
                    hosts.append(h)
            elif isinstance(line, str) and line:
                hosts.append(line.split("/")[0])
        hosts = list(dict.fromkeys(hosts))
        out, res = run_nmap_ports(hosts, mods.port_scan.ports)
        if res:
            _log_step(
                db, scan.id, "port_scan", res.status, {"preview_chars": len(out)}, res
            )
            persist_scan_artifact(
                db,
                scan_id=scan.id,
                module="port_scan",
                tool="nmap",
                summary_json={"hosts_scanned": len(hosts)},
                text_preview=out[:65000],
            )
        return payload
    finally:
        db.close()


@celery_app.task(name="app.tasks.scan_tasks.scan_stage_screenshots")
def scan_stage_screenshots(payload: dict) -> dict:
    return asyncio.run(_scan_stage_screenshots_async(payload))


async def _scan_stage_screenshots_async(payload: dict) -> dict:
    if not isinstance(payload, dict):
        raise ValueError("Invalid payload")
    scan_id = payload.get("scan_id")
    if not scan_id or not isinstance(scan_id, int):
        raise ValueError("Invalid scan_id")
    db = get_sessionmaker()()
    try:
        scan, target = await _load_scan(scan_id, db)
        if not scan or not target:
            return payload
        _set_stage(scan, db, "screenshots")
        mods = parse_modules_from_config(scan.scan_config_json or {})
        live = payload.get("live_hosts") or []
        lines = [u for u in live if isinstance(u, str) and u.startswith("http")]
        out_dir = f"/tmp/gowitness_scan_{scan.id}"
        _, res = run_gowitness_screenshots(
            lines, out_dir, mods.screenshots.delay_seconds
        )
        if res:
            _log_step(db, scan.id, "screenshots", res.status, {"out_dir": out_dir}, res)
            persist_scan_artifact(
                db,
                scan_id=scan.id,
                module="screenshots",
                tool="gowitness",
                summary_json={"out_dir": out_dir, "seeds": len(lines)},
                text_preview=out_dir,
            )
        return payload
    finally:
        db.close()


@celery_app.task(name="app.tasks.scan_tasks.scan_stage_waf_fingerprint")
def scan_stage_waf_fingerprint(payload: dict) -> dict:
    return asyncio.run(_scan_stage_waf_fingerprint_async(payload))


async def _scan_stage_waf_fingerprint_async(payload: dict) -> dict:
    if not isinstance(payload, dict):
        raise ValueError("Invalid payload")
    scan_id = payload.get("scan_id")
    if not scan_id or not isinstance(scan_id, int):
        raise ValueError("Invalid scan_id")
    db = get_sessionmaker()()
    try:
        scan, target = await _load_scan(scan_id, db)
        if not scan or not target:
            return payload
        _set_stage(scan, db, "waf_fingerprint")
        mods = parse_modules_from_config(scan.scan_config_json or {})
        live = [
            u
            for u in (payload.get("live_hosts") or [])
            if isinstance(u, str) and u.startswith("http")
        ]
        sample = live[: mods.waf_fingerprint.sample_size]
        out, res = run_wafw00f_sample(sample)
        if res:
            _log_step(
                db, scan.id, "waf_fingerprint", res.status, {"sample": len(sample)}, res
            )
            persist_scan_artifact(
                db,
                scan_id=scan.id,
                module="waf_fingerprint",
                tool="wafw00f",
                summary_json={"urls": len(sample)},
                text_preview=out[:65000] if out else None,
            )
        return payload
    finally:
        db.close()


@celery_app.task(name="app.tasks.scan_tasks.scan_stage_gau")
def scan_stage_gau(payload: dict) -> dict:
    return asyncio.run(_scan_stage_gau_async(payload))


async def _scan_stage_gau_async(payload: dict) -> dict:
    # Validate payload structure
    if not isinstance(payload, dict):
        raise ValueError("Invalid payload: expected dictionary")

    scan_id = payload.get("scan_id")
    if not scan_id or not isinstance(scan_id, int):
        raise ValueError("Invalid or missing scan_id in payload")

    db = get_sessionmaker()()
    try:
        scan, target = await _load_scan(scan_id, db)
        if not scan or not target:
            return payload
        _set_stage(scan, db, "gau")

        live_hosts = payload.get("live_hosts", [])
        if not live_hosts:
            _soft_log(
                scan,
                db,
                "gau",
                {"error": "No live hosts to scan"},
                warning="No live hosts available",
            )
            return payload

        urls, gau_result = run_gau(live_hosts)
        _log_step(
            db,
            scan.id,
            "gau",
            gau_result.status,
            {"count": len(urls), "parsed_json": {"raw_urls": urls[:200]}},
            gau_result,
        )
        if gau_result.status != "success":
            _fail_scan(scan, db, stage="gau", message=gau_result.error or "gau failed")
            raise RuntimeError(gau_result.error or "gau failed")

        normalized = normalize_and_dedupe_urls(urls, source="gau")
        _upsert_endpoints(db, scan.id, normalized)

        js_candidates = select_javascript_assets(normalized)
        asset_rows, derived_endpoints = analyze_javascript_assets(
            js_candidates, {target.domain} | {row.hostname for row in scan.subdomains}
        )
        if asset_rows:
            _create_js_assets(db, scan.id, asset_rows)
            _log_step(
                db,
                scan.id,
                "javascript_analysis",
                "success",
                {
                    "count": len(asset_rows),
                    "parsed_json": {
                        "assets": [
                            {
                                "url": row["url"],
                                "status": row["status"],
                                "secret_count": len(row["secrets_json"]),
                            }
                            for row in asset_rows
                        ]
                    },
                },
            )
        else:
            _soft_log(
                scan,
                db,
                "javascript_analysis",
                {"count": 0, "parsed_json": {"assets": []}},
            )

        if derived_endpoints:
            _upsert_endpoints(db, scan.id, derived_endpoints)
        nuclei_targets = filter_nuclei_targets(normalized + derived_endpoints)

        # AI-powered JavaScript and endpoint analysis
        try:
            js_urls = [row["url"] for row in js_candidates if row.get("url")]
            endpoint_urls = [
                row["normalized_url"] for row in normalized + derived_endpoints
            ]
            if js_urls or endpoint_urls or asset_rows:
                js_summaries = (
                    build_javascript_asset_summaries_for_ai(asset_rows)
                    if asset_rows
                    else []
                )
                ai_analysis = await analyze_javascript_endpoints(
                    js_urls, endpoint_urls, asset_summaries=js_summaries or None
                )
                if ai_analysis and "high_value_targets" in ai_analysis:
                    _soft_log(
                        scan,
                        db,
                        "ai_javascript_analysis",
                        {
                            "high_value_count": len(
                                ai_analysis.get("high_value_targets", [])
                            ),
                            "potential_leaks": len(
                                ai_analysis.get("potential_leaks", [])
                            ),
                            "suggested_templates": ai_analysis.get(
                                "suggested_nuclei_templates", []
                            ),
                            "js_files_analyzed": len(js_urls),
                            "endpoints_analyzed": len(endpoint_urls),
                        },
                    )
                    # Store AI insights in scan metadata
                    metadata = _merge_metadata(scan)
                    metadata["ai_javascript_analysis"] = ai_analysis
                    _update_scan(scan, db, metadata_json=metadata)
        except Exception as e:
            _soft_log(
                scan,
                db,
                "ai_javascript_analysis",
                {"error": str(e)[:200]},
                warning="AI JavaScript analysis failed",
            )

        return payload | {"nuclei_targets": nuclei_targets}
    finally:
        db.close()


@celery_app.task(name="app.tasks.scan_tasks.scan_stage_waybackurls")
def scan_stage_waybackurls(payload: dict) -> dict:
    return asyncio.run(_scan_stage_waybackurls_async(payload))


async def _scan_stage_waybackurls_async(payload: dict) -> dict:
    if not isinstance(payload, dict):
        raise ValueError("Invalid payload")
    scan_id = payload.get("scan_id")
    if not scan_id or not isinstance(scan_id, int):
        raise ValueError("Invalid scan_id")
    db = get_sessionmaker()()
    try:
        scan, target = await _load_scan(scan_id, db)
        if not scan or not target:
            return payload
        _set_stage(scan, db, "waybackurls")
        urls, res = run_waybackurls(target.domain)
        if res:
            _log_step(
                db,
                scan.id,
                "waybackurls",
                res.status,
                {"count": len(urls), "parsed_json": {"urls": urls[:100]}},
                res,
            )
        if urls:
            normalized = normalize_and_dedupe_urls(urls, source="wayback")
            _upsert_endpoints(db, scan.id, normalized)
        return payload
    finally:
        db.close()


@celery_app.task(name="app.tasks.scan_tasks.scan_stage_katana")
def scan_stage_katana(payload: dict) -> dict:
    return asyncio.run(_scan_stage_katana_async(payload))


async def _scan_stage_katana_async(payload: dict) -> dict:
    if not isinstance(payload, dict):
        raise ValueError("Invalid payload")
    scan_id = payload.get("scan_id")
    if not scan_id or not isinstance(scan_id, int):
        raise ValueError("Invalid scan_id")
    db = get_sessionmaker()()
    try:
        scan, target = await _load_scan(scan_id, db)
        if not scan or not target:
            return payload
        _set_stage(scan, db, "katana")
        mods = parse_modules_from_config(scan.scan_config_json or {})
        live = [
            u
            for u in (payload.get("live_hosts") or [])
            if isinstance(u, str) and u.startswith("http")
        ]
        seeds = live[:5] if live else [f"https://{target.domain}"]
        urls, res = run_katana(seeds, mods.url_sources.katana_depth)
        if res:
            _log_step(
                db,
                scan.id,
                "katana",
                res.status,
                {"count": len(urls), "parsed_json": {"urls": urls[:100]}},
                res,
            )
        if urls:
            normalized = normalize_and_dedupe_urls(urls, source="katana")
            _upsert_endpoints(db, scan.id, normalized)
        return payload
    finally:
        db.close()


@celery_app.task(name="app.tasks.scan_tasks.scan_stage_ffuf_dir")
def scan_stage_ffuf_dir(payload: dict) -> dict:
    return asyncio.run(_scan_stage_ffuf_dir_async(payload))


async def _scan_stage_ffuf_dir_async(payload: dict) -> dict:
    if not isinstance(payload, dict):
        raise ValueError("Invalid payload")
    scan_id = payload.get("scan_id")
    if not scan_id or not isinstance(scan_id, int):
        raise ValueError("Invalid scan_id")
    db = get_sessionmaker()()
    try:
        scan, target = await _load_scan(scan_id, db)
        if not scan or not target:
            return payload
        _set_stage(scan, db, "ffuf_dir")
        mods = parse_modules_from_config(scan.scan_config_json or {})
        base = (mods.content_discovery.base_url or "").strip()
        if not base:
            base = f"https://{target.domain}"
        wl = mods.content_discovery.wordlist_path or ""
        if not wl and settings.seclists_base_path:
            wl = f"{settings.seclists_base_path}/Discovery/Web-Content/common.txt"
        max_m = mods.content_discovery.max_matches
        urls, res = run_ffuf_dirs(base, wl, max_m)
        if res:
            _log_step(
                db,
                scan.id,
                "ffuf_dir",
                res.status,
                {"count": len(urls), "parsed_json": {"urls": urls[:100]}},
                res,
            )
        if urls:
            normalized = normalize_and_dedupe_urls(urls, source="ffuf")
            _upsert_endpoints(db, scan.id, normalized)
        return payload
    finally:
        db.close()


@celery_app.task(name="app.tasks.scan_tasks.scan_stage_aggressive")
def scan_stage_aggressive(payload: dict) -> dict:
    return asyncio.run(_scan_stage_aggressive_async(payload))


async def _scan_stage_aggressive_async(payload: dict) -> dict:
    if not isinstance(payload, dict):
        raise ValueError("Invalid payload")
    scan_id = payload.get("scan_id")
    if not scan_id or not isinstance(scan_id, int):
        raise ValueError("Invalid scan_id")
    db = get_sessionmaker()()
    try:
        scan, target = await _load_scan(scan_id, db)
        if not scan or not target:
            return payload
        if not settings.enable_aggressive_scanning:
            _soft_log(
                scan,
                db,
                "aggressive",
                {"skipped": "enable_aggressive_scanning is false"},
            )
            return payload
        mods = parse_modules_from_config(scan.scan_config_json or {})
        if not mods.aggressive.enabled:
            return payload
        _set_stage(scan, db, "aggressive")
        rows = db.query(Endpoint).filter(Endpoint.scan_id == scan.id).all()
        param_urls = sorted(
            {
                row.url
                for row in rows
                if "?" in (row.url or "")
                and row.url.startswith(
                    tuple(f"{s}://" for s in settings.allowed_schemes)
                )
            }
        )
        previews: list[str] = []
        if mods.aggressive.run_sqlmap:
            for url in param_urls[: settings.scan_sqlmap_max_urls]:
                out, res = run_sqlmap_batch(url)
                if res:
                    previews.append(f"=== sqlmap {url}\n{out[:8000]}")
                    _log_step(db, scan.id, "sqlmap", res.status, {"url": url}, res)
        if mods.aggressive.run_dalfox:
            for url in param_urls[: settings.scan_dalfox_max_urls]:
                out, res = run_dalfox_url(url)
                if res:
                    previews.append(f"=== dalfox {url}\n{out[:8000]}")
                    _log_step(db, scan.id, "dalfox", res.status, {"url": url}, res)
        if mods.aggressive.run_masscan and payload.get("live_hosts"):
            live = payload.get("live_hosts") or []
            hosts = []
            for line in live:
                if isinstance(line, str) and "://" not in line and line:
                    hosts.append(line.split("/")[0])
            hosts = list(dict.fromkeys(hosts))[: settings.scan_masscan_max_hosts]
            for h in hosts[:1]:
                out, res = run_masscan_hosts([h], settings.scan_masscan_rate)
                if res:
                    previews.append(f"=== masscan {h}\n{out[:8000]}")
                    _log_step(db, scan.id, "masscan", res.status, {"host": h}, res)
        if previews:
            persist_scan_artifact(
                db,
                scan_id=scan.id,
                module="aggressive",
                tool="mixed",
                summary_json={"sections": len(previews)},
                text_preview="\n\n".join(previews)[:65000],
            )
        return payload
    finally:
        db.close()


@celery_app.task(name="app.tasks.scan_tasks.scan_stage_nuclei")
def scan_stage_nuclei(payload: dict) -> dict:
    return asyncio.run(_scan_stage_nuclei_async(payload))


async def _scan_stage_nuclei_async(payload: dict) -> dict:
    # Validate payload structure
    if not isinstance(payload, dict):
        raise ValueError("Invalid payload: expected dictionary")

    scan_id = payload.get("scan_id")
    if not scan_id or not isinstance(scan_id, int):
        raise ValueError("Invalid or missing scan_id in payload")

    db = get_sessionmaker()()
    try:
        scan, target = await _load_scan(scan_id, db)
        if not scan or not target:
            return payload
        _set_stage(scan, db, "nuclei")

        scan_config = dict(scan.scan_config_json or {})
        mods = parse_modules_from_config(scan.scan_config_json or {})
        scan_config["nuclei_extras"] = mods.nuclei_extras.model_dump()
        nuclei_targets = _nuclei_targets_from_scan_endpoints(db, scan.id)
        if not nuclei_targets:
            nuclei_targets = list(payload.get("nuclei_targets") or [])
        if not nuclei_targets:
            _soft_log(
                scan,
                db,
                "nuclei",
                {"error": "No targets to scan"},
                warning="No nuclei targets available",
            )

        vulnerabilities, nuclei_result = run_nuclei(nuclei_targets, scan_config)
        if nuclei_result:
            command_preview = " ".join(
                shlex.quote(part) for part in nuclei_result.command
            )
            _log_step(
                db,
                scan.id,
                "nuclei",
                nuclei_result.status,
                {
                    "count": len(vulnerabilities),
                    "scan_config": scan_config,
                    "effective_nuclei_command": command_preview,
                    "parsed_json": {"vulnerabilities": vulnerabilities[:100]},
                },
                nuclei_result,
            )
        else:
            _log_step(
                db,
                scan.id,
                "nuclei",
                "success",
                {
                    "count": 0,
                    "scan_config": scan_config,
                    "parsed_json": {"vulnerabilities": []},
                },
            )
        if nuclei_result and nuclei_result.status != "success":
            _fail_scan(
                scan, db, stage="nuclei", message=nuclei_result.error or "nuclei failed"
            )
            raise RuntimeError(nuclei_result.error or "nuclei failed")

        _create_vulnerabilities(db, scan.id, vulnerabilities)

        # AI-powered nuclei findings analysis for vulnerability chaining
        try:
            if vulnerabilities:
                nuclei_output = "\n".join(
                    [
                        f"{vuln.get('template_id', 'unknown')}: {vuln.get('matched_url', 'N/A')} - {vuln.get('severity', 'unknown')}"
                        for vuln in vulnerabilities[:50]
                    ]
                )
                ai_analysis = await analyze_nuclei_findings(nuclei_output)
                if ai_analysis and "high_value_targets" in ai_analysis:
                    _soft_log(
                        scan,
                        db,
                        "ai_nuclei_analysis",
                        {
                            "high_value_count": len(
                                ai_analysis.get("high_value_targets", [])
                            ),
                            "potential_leaks": len(
                                ai_analysis.get("potential_leaks", [])
                            ),
                            "suggested_templates": ai_analysis.get(
                                "suggested_nuclei_templates", []
                            ),
                            "vulnerabilities_analyzed": min(len(vulnerabilities), 50),
                        },
                    )
                    # Store AI insights in scan metadata
                    metadata = _merge_metadata(scan)
                    metadata["ai_nuclei_analysis"] = ai_analysis
                    _update_scan(scan, db, metadata_json=metadata)
        except Exception as e:
            _soft_log(
                scan,
                db,
                "ai_nuclei_analysis",
                {"error": str(e)[:200]},
                warning="AI nuclei analysis failed",
            )

        endpoints = (
            db.query(Endpoint)
            .filter(Endpoint.scan_id == scan.id)
            .order_by(Endpoint.priority_score.desc())
            .all()
        )
        js_assets = (
            db.query(JavaScriptAsset).filter(JavaScriptAsset.scan_id == scan.id).all()
        )
        subdomains = db.query(Subdomain).filter(Subdomain.scan_id == scan.id).all()

        header_findings, headers_result = check_headers(
            [row.url for row in endpoints[: settings.scan_header_probe_cap]]
        )
        if headers_result:
            _log_step(
                db,
                scan.id,
                "header_analysis",
                headers_result.status,
                {
                    "count": len(header_findings),
                    "parsed_json": {"vulnerabilities": header_findings},
                },
                headers_result,
            )
            if headers_result.status != "success":
                _append_warning(
                    scan, db, headers_result.error or "header analysis failed"
                )
        else:
            _soft_log(
                scan,
                db,
                "header_analysis",
                {"count": 0, "parsed_json": {"vulnerabilities": []}},
            )

        heuristic_findings = synthesize_heuristic_findings(
            endpoints, js_assets, subdomains
        )
        if header_findings:
            heuristic_findings.extend(header_findings)
        _create_vulnerabilities(db, scan.id, heuristic_findings)
        _log_step(
            db,
            scan.id,
            "correlation",
            "success",
            {
                "count": len(heuristic_findings),
                "parsed_json": {"vulnerabilities": heuristic_findings[:100]},
            },
        )

        # Generate professional reports for high/critical findings
        await _generate_ai_reports(db, scan, vulnerabilities + heuristic_findings)

        # NEW: Advanced Reconnaissance Stages
        await _run_advanced_recon_stages(db, scan, target)

        refreshed_scan, _ = await _load_scan(scan.id, db)
        if not refreshed_scan:
            return payload
        ranked_attack_paths = rank_attack_paths(
            refreshed_scan.endpoints, refreshed_scan.vulnerabilities
        )
        _create_attack_paths(db, scan.id, ranked_attack_paths)
        _log_step(
            db,
            scan.id,
            "attack_path_generation",
            "success",
            {
                "count": len(ranked_attack_paths),
                "parsed_json": {"attack_paths": ranked_attack_paths[:25]},
            },
        )

        # Detect payload testing opportunities
        try:
            _detect_payload_opportunities(db, scan.id)
            opp_count = (
                db.query(PayloadOpportunity)
                .filter(PayloadOpportunity.scan_id == scan.id)
                .count()
            )
            _log_step(
                db,
                scan.id,
                "payload_opportunity_detection",
                "success",
                {"count": opp_count, "parsed_json": {}},
            )
        except Exception as e:
            _soft_log(
                scan,
                db,
                "payload_opportunity_detection",
                {"count": 0},
                warning=str(e)[:200],
            )

        refreshed_scan, _ = await _load_scan(scan.id, db)
        if refreshed_scan:
            _compute_diff_and_notifications(db, refreshed_scan, target)
            stages_done = (refreshed_scan.metadata_json or {}).get(
                "pipeline_stages"
            ) or [
                "subfinder",
                "httpx",
                "gau",
                "nuclei",
            ]
            st_total = len(stages_done)
            metadata = _merge_metadata(
                refreshed_scan,
                stage="completed",
                stage_index=st_total,
                stage_total=st_total,
                progress_percent=100,
            )
            _update_scan(refreshed_scan, db, status="completed", metadata_json=metadata)

            # Send WebSocket notification for scan completion
            results = {
                "subdomains_count": len(refreshed_scan.subdomains),
                "vulnerabilities_count": len(refreshed_scan.vulnerabilities),
                "endpoints_count": len(refreshed_scan.endpoints),
                "attack_paths_count": len(refreshed_scan.attack_paths),
            }
            await notify_scan_completed(
                target.owner_id, target.domain, refreshed_scan.id, results
            )

            # Send notifications for critical vulnerabilities
            for vuln in refreshed_scan.vulnerabilities:
                if vuln.severity in ["high", "critical"]:
                    vuln_payload = {
                        "id": vuln.id,
                        "template_id": vuln.template_id,
                        "severity": vuln.severity,
                        "matched_url": vuln.matched_url,
                        "description": vuln.description,
                    }

                    # Internal websocket notification
                    if vuln.severity == "critical":
                        await notify_critical_vulnerability(
                            target.owner_id, vuln_payload
                        )

                    # External notifications (Slack/Discord)
                    await notification_service.notify_critical_finding(vuln_payload)

        return {"scan_id": scan.id, "status": "completed"}
    finally:
        db.close()


STAGE_REGISTRY: dict[str, object] = {
    "passive_dns": scan_stage_passive_dns,
    "subfinder": scan_stage_subfinder,
    "active_dns": scan_stage_active_dns,
    "httpx": scan_stage_httpx,
    "port_scan": scan_stage_port_scan,
    "screenshots": scan_stage_screenshots,
    "waf_fingerprint": scan_stage_waf_fingerprint,
    "gau": scan_stage_gau,
    "waybackurls": scan_stage_waybackurls,
    "katana": scan_stage_katana,
    "ffuf_dir": scan_stage_ffuf_dir,
    "aggressive": scan_stage_aggressive,
    "nuclei": scan_stage_nuclei,
}


def start_scan_chain(scan_id: int) -> None:
    sm = get_sessionmaker()()
    try:
        scan = sm.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            logger.error("start_scan_chain: scan %s not found", scan_id)
            return
        stages = resolve_pipeline_stages(scan.scan_config_json)
        meta = dict(scan.metadata_json or {})
        meta["pipeline_stages"] = stages
        meta["stage_total"] = len(stages)
        scan.metadata_json = meta
        sm.add(scan)
        sm.commit()
    finally:
        sm.close()

    task_objs = [STAGE_REGISTRY[name] for name in stages]
    if not task_objs:
        logger.error("start_scan_chain: empty pipeline for scan %s", scan_id)
        return
    header = task_objs[0].s(scan_id)  # type: ignore[union-attr]
    tail = [t.s() for t in task_objs[1:]]  # type: ignore[union-attr]
    chain(header, *tail).apply_async()


@celery_app.task(name="app.tasks.scan_tasks.check_scheduled_scans")
def check_scheduled_scans() -> dict:
    db = get_sessionmaker()()
    try:
        now = datetime.now(timezone.utc)
        due_schedules = (
            db.query(ScheduledScan)
            .filter(ScheduledScan.enabled.is_(True), ScheduledScan.next_run <= now)
            .all()
        )
        created = 0
        for schedule in due_schedules:
            running = (
                db.query(Scan)
                .filter(
                    Scan.target_id == schedule.target_id,
                    Scan.status.in_(["pending", "running"]),
                )
                .first()
            )
            if running:
                continue
            sched_cfg = schedule.scan_config_json or {}
            scan = Scan(
                target_id=schedule.target_id,
                status="pending",
                metadata_json=_default_metadata(
                    "queued", 0, pipeline_stage_total(sched_cfg)
                )
                | {"scheduled": True},
                scan_config_json=sched_cfg,
            )
            db.add(scan)
            try:
                db.commit()
            except IntegrityError:
                db.rollback()
                continue
            db.refresh(scan)
            start_scan_chain(scan.id)
            created += 1

            schedule.last_run = now
            if schedule.frequency == "weekly":
                schedule.next_run = now + timedelta(weeks=1)
            else:
                schedule.next_run = now + timedelta(days=1)
            db.commit()
        return {"checked": len(due_schedules), "created": created}
    finally:
        db.close()


async def _run_advanced_recon_stages(db: Session, scan: Scan, target: Target) -> None:
    """Run advanced reconnaissance stages: parameter discovery and content fuzzing."""

    try:
        # Get stealth configuration for target
        from app.models.advanced_recon import StealthConfig

        stealth_config = (
            db.query(StealthConfig).filter(StealthConfig.target_id == target.id).first()
        )

        if not stealth_config:
            # Create default stealth config
            stealth_config = StealthConfig(
                target_id=target.id,
                scan_mode="balanced",
                requests_per_second=5,
                random_delay_min=100,
                random_delay_max=500,
                concurrent_threads=2,
                max_retries=3,
                retry_backoff_factor=2,
                rotate_user_agents=True,
                use_jitter=True,
                jitter_percentage=20,
                respect_robots_txt=True,
            )
            db.add(stealth_config)
            db.commit()

        # Get endpoints for parameter discovery
        endpoints = db.query(Endpoint).filter(Endpoint.scan_id == scan.id).all()
        endpoint_urls = [
            endpoint.url for endpoint in endpoints[:50]
        ]  # Limit to 50 endpoints

        if endpoint_urls:
            # Stage 5: Parameter Discovery
            _log_step(
                db,
                scan.id,
                "parameter_discovery",
                "running",
                {
                    "endpoint_count": len(endpoint_urls),
                    "scan_mode": stealth_config.scan_mode,
                },
            )

            # Run parameter discovery
            from app.services.advanced_recon_engine import (
                parameter_discovery,
                stealth_scanner,
            )

            param_discovery = parameter_discovery()

            async with stealth_scanner(stealth_config) as scanner:
                discovered_params = await param_discovery.discover_parameters(
                    endpoint_urls[0], scanner, scan.id  # Use first endpoint as base
                )

                # Store discovered parameters
                for param in discovered_params:
                    db.add(param)
                db.commit()

            _log_step(
                db,
                scan.id,
                "parameter_discovery",
                "success",
                {"parameters_discovered": len(discovered_params)},
            )

            # Stage 6: Content Fuzzing
            _log_step(
                db,
                scan.id,
                "content_fuzzing",
                "running",
                {"scan_mode": stealth_config.scan_mode},
            )

            # Run content fuzzing on base URLs
            from app.services.advanced_recon_engine import content_fuzzer

            fuzzing_engine = content_fuzzer()

            base_urls = [f"https://{target.domain}"]
            fuzzed_endpoints = []

            async with stealth_scanner(stealth_config) as scanner:
                # Fuzz admin paths
                admin_endpoints = await fuzzing_engine.fuzz_content(
                    base_urls[0], "admin", scanner, scan.id
                )
                fuzzed_endpoints.extend(admin_endpoints)

                # Fuzz API paths
                api_endpoints = await fuzzing_engine.fuzz_content(
                    base_urls[0], "api", scanner, scan.id
                )
                fuzzed_endpoints.extend(api_endpoints)

                # Store fuzzed endpoints
                for endpoint in fuzzed_endpoints:
                    db.add(endpoint)
                db.commit()

            _log_step(
                db,
                scan.id,
                "content_fuzzing",
                "success",
                {"endpoints_discovered": len(fuzzed_endpoints)},
            )

            # Stage 7: Adaptive Analysis
            _log_step(
                db,
                scan.id,
                "adaptive_analysis",
                "running",
                {"endpoints_analyzed": len(endpoints)},
            )

            # Run adaptive analysis
            from app.services.advanced_recon_engine import adaptive_scanner

            adaptive = adaptive_scanner()

            adaptive_results = []
            for endpoint in endpoints[:20]:  # Limit to 20 endpoints
                try:
                    import httpx

                    async with httpx.AsyncClient(timeout=10) as client:
                        response = await client.get(endpoint.url)
                        analysis = adaptive.analyze_endpoint(endpoint.url, response)

                        adaptive_results.append(
                            {
                                "endpoint_url": endpoint.url,
                                "analysis": analysis,
                                "recommendations": analysis.get(
                                    "recommended_techniques", []
                                ),
                                "priority": analysis.get("priority_level", "medium"),
                            }
                        )
                except Exception as e:
                    logger.warning(f"Adaptive analysis failed for {endpoint.url}: {e}")
                    continue

            # Store adaptive results in scan metadata
            metadata = _merge_metadata(scan)
            metadata["adaptive_analysis"] = adaptive_results
            metadata["advanced_recon_completed"] = datetime.now(
                timezone.utc
            ).isoformat()
            _update_scan(scan, db, metadata_json=metadata)

            _log_step(
                db,
                scan.id,
                "adaptive_analysis",
                "success",
                {"adaptive_results": len(adaptive_results)},
            )

        else:
            _log_step(
                db,
                scan.id,
                "advanced_recon",
                "skipped",
                {"reason": "no_endpoints_available"},
            )

    except Exception as e:
        logger.error(f"Advanced recon stages failed for scan {scan.id}: {e}")
        _log_step(db, scan.id, "advanced_recon", "failed", {"error": str(e)})
