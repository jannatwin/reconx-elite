from __future__ import annotations

import shlex
from datetime import datetime, timedelta, timezone

from celery import chain
from sqlalchemy.orm import Session, selectinload

from app.core.config import settings
from app.core.database import get_sessionmaker
from app.models.attack_path import AttackPath
from app.models.endpoint import Endpoint
from app.models.javascript_asset import JavaScriptAsset
from app.models.notification import Notification
from app.models.payload_opportunity import PayloadOpportunity
from app.models.scan import Scan
from app.models.scan_diff import ScanDiff
from app.models.scan_log import ScanLog
from app.models.scheduled_scan import ScheduledScan
from app.models.subdomain import Subdomain
from app.models.target import Target
from app.models.vulnerability import Vulnerability
from app.services.intelligence import (
    analyze_javascript_assets,
    build_subdomain_record,
    filter_nuclei_targets,
    normalize_and_dedupe_urls,
    rank_attack_paths,
    select_javascript_assets,
    synthesize_heuristic_findings,
)
from app.services.blind_xss_service import BlindXssService
from app.services.payload_generator import PayloadGenerator
from app.services.payload_tester import OpportunityDetector
from app.services.scan_runner import check_headers, run_gau, run_httpx, run_httpx_enrich, run_nuclei, run_subfinder
from app.services.ssrf_service import SsrfService
from app.services.tool_executor import ToolExecutionResult
from app.tasks.celery_app import celery_app

STAGES = [("subfinder", 1), ("httpx", 2), ("gau", 3), ("nuclei", 4)]
TOTAL_STAGES = len(STAGES)


def _default_metadata(stage: str = "queued", stage_index: int = 0) -> dict:
    return {
        "stage": stage,
        "stage_index": stage_index,
        "stage_total": TOTAL_STAGES,
        "progress_percent": int((stage_index / TOTAL_STAGES) * 100) if stage_index else 0,
        "warnings": [],
        "errors": [],
    }


def _load_scan(scan_id: int, db: Session) -> tuple[Scan | None, Target | None]:
    scan = (
        db.query(Scan)
        .options(
            selectinload(Scan.target),
            selectinload(Scan.subdomains),
            selectinload(Scan.endpoints),
            selectinload(Scan.vulnerabilities),
            selectinload(Scan.javascript_assets),
            selectinload(Scan.attack_paths),
            selectinload(Scan.logs),
            selectinload(Scan.diffs),
        )
        .filter(Scan.id == scan_id)
        .first()
    )
    if not scan:
        return None, None
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


def _set_stage(scan: Scan, db: Session, stage: str, stage_index: int) -> None:
    metadata = _merge_metadata(
        scan,
        stage=stage,
        stage_index=stage_index,
        stage_total=TOTAL_STAGES,
        progress_percent=int(((stage_index - 1) / TOTAL_STAGES) * 100),
    )
    _update_scan(scan, db, status="running", metadata_json=metadata)


def _append_warning(scan: Scan, db: Session, message: str) -> None:
    metadata = _merge_metadata(scan)
    warnings = list(metadata.get("warnings") or [])
    warnings.append(message)
    metadata["warnings"] = warnings[-20:]
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
        progress_percent=min(int((scan.metadata_json or {}).get("progress_percent", 0)), 99),
    )
    _update_scan(scan, db, status="failed", error=message, metadata_json=metadata)


def _soft_log(scan: Scan, db: Session, step: str, payload: dict, warning: str | None = None) -> None:
    if warning:
        _append_warning(scan, db, f"{step}: {warning}")
    _log_step(db, scan.id, step, "warning" if warning else "success", payload)


def _upsert_endpoints(db: Session, scan_id: int, records: list[dict]) -> None:
    existing = {
        row.normalized_url: row
        for row in db.query(Endpoint).filter(Endpoint.scan_id == scan_id).all()
    }
    for record in records:
        normalized_url = record["normalized_url"]
        row = existing.get(normalized_url)
        if row:
            row.priority_score = max(row.priority_score, record["priority_score"])
            row.focus_reasons = sorted(set(row.focus_reasons or []) | set(record["focus_reasons"]))
            row.tags = sorted(set(row.tags or []) | set(record["tags"]))
            row.is_interesting = row.is_interesting or record["is_interesting"]
            row.category = row.category if row.category != "general" else record["category"]
            if row.source == "gau" and record["source"] == "js":
                row.js_source = record["js_source"] or row.js_source
            elif row.source == "js" and record["source"] == "gau":
                row.source = "gau"
        else:
            db.add(Endpoint(scan_id=scan_id, **{k: v for k, v in record.items() if not k.startswith("is_")}))
    db.commit()


def _create_js_assets(db: Session, scan_id: int, asset_rows: list[dict]) -> None:
    for row in asset_rows:
        db.add(JavaScriptAsset(scan_id=scan_id, **row))
    db.commit()


def _create_vulnerabilities(db: Session, scan_id: int, vulnerabilities: list[dict]) -> None:
    existing = {
        (row.template_id, row.matched_url or "", row.matcher_name or "")
        for row in db.query(Vulnerability).filter(Vulnerability.scan_id == scan_id).all()
    }
    for vulnerability in vulnerabilities:
        key = (
            vulnerability["template_id"],
            vulnerability.get("matched_url") or "",
            vulnerability.get("matcher_name") or "",
        )
        if key in existing:
            continue
        existing.add(key)
        db.add(Vulnerability(scan_id=scan_id, **vulnerability))
    db.commit()


def _create_attack_paths(db: Session, scan_id: int, attack_paths: list[dict]) -> None:
    for attack_path in attack_paths:
        db.add(AttackPath(scan_id=scan_id, **attack_path))
    db.commit()


def _detect_payload_opportunities(db: Session, scan_id: int) -> None:
    """Detect and store payload testing opportunities for endpoints in this scan."""
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
            existing = db.query(PayloadOpportunity).filter(
                PayloadOpportunity.endpoint_id == endpoint.id,
                PayloadOpportunity.parameter_name == opp["parameter_name"],
                PayloadOpportunity.vulnerability_type.in_(opp["vulnerability_types"]),
            ).first()
            
            if existing:
                continue
            
            for vuln_type in opp["vulnerability_types"]:
                payloads = PayloadGenerator.get_payloads_for_type(vuln_type)

                # For blind XSS, generate payloads with tokens
                if vuln_type == "blind_xss":
                    # Get user ID from target owner
                    user_id = target.owner_id
                    token = BlindXssService.create_token_for_opportunity(db, user_id, None)  # Will be updated with opp ID after creation

                    # Replace __TOKEN__ placeholder with actual token and domain
                    domain = target.domain  # Use target domain as base
                    modified_payloads = []
                    for payload in payloads[:3]:  # Only use first 3 blind XSS payloads
                        modified_payload = BlindXssService.create_payload_with_token(payload, token, domain)
                        modified_payloads.append(modified_payload)

                    payloads = modified_payloads

                # For SSRF, generate payloads with tokens
                elif vuln_type == "ssrf":
                    # Get user ID from target owner
                    user_id = target.owner_id
                    token = SsrfService.create_token_for_opportunity(db, user_id, None)  # Will be updated with opp ID after creation

                    # Replace __TOKEN__ placeholder with actual token and domain
                    domain = settings.backend_callback_url.split("://")[-1]  # Use callback backend URL
                    modified_payloads = []
                    for payload in payloads[:5]:  # Use first 5 SSRF payloads
                        modified_payload = SsrfService.create_payload_with_token(payload, token, domain)
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
                    token_entry = db.query(BlindXssHit).filter(
                        BlindXssHit.user_id == target.owner_id,
                        BlindXssHit.payload_opportunity_id.is_(None)
                    ).order_by(BlindXssHit.triggered_at.desc()).first()

                    if token_entry:
                        token_entry.payload_opportunity_id = db_opp.id

                # For SSRF, update the token with the opportunity ID
                elif vuln_type == "ssrf":
                    # Find the token entry and update it
                    token_entry = db.query(SsrfSignal).filter(
                        SsrfSignal.user_id == target.owner_id,
                        SsrfSignal.payload_opportunity_id.is_(None)
                    ).order_by(SsrfSignal.triggered_at.desc()).first()

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


def _compute_diff_and_notifications(db: Session, scan: Scan, target: Target) -> None:
    previous_scan = (
        db.query(Scan)
        .options(
            selectinload(Scan.subdomains),
            selectinload(Scan.endpoints),
            selectinload(Scan.vulnerabilities),
        )
        .filter(Scan.target_id == scan.target_id, Scan.id != scan.id, Scan.status == "completed")
        .order_by(Scan.created_at.desc())
        .first()
    )
    if not previous_scan:
        return

    current_subdomains = {row.hostname for row in scan.subdomains}
    current_endpoints = {row.normalized_url for row in scan.endpoints}
    current_vulns = {(row.template_id, row.matched_url or "", row.matcher_name or "") for row in scan.vulnerabilities}

    prev_subdomains = {row.hostname for row in previous_scan.subdomains}
    prev_endpoints = {row.normalized_url for row in previous_scan.endpoints}
    prev_vulns = {(row.template_id, row.matched_url or "", row.matcher_name or "") for row in previous_scan.vulnerabilities}

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
        if (row.template_id, row.matched_url or "", row.matcher_name or "") not in prev_vulns
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
                metadata_json={"target_id": target.id, "scan_id": scan.id, "new_subdomains": new_subdomains},
            )
        )
    if new_vulns:
        db.add(
            Notification(
                user_id=target.owner_id,
                type="new_vulnerability",
                message=f"New vulnerabilities found for {target.domain}: {len(new_vulns)} new issue(s)",
                metadata_json={"target_id": target.id, "scan_id": scan.id, "new_vulnerabilities": new_vulns},
            )
        )
    db.commit()


def start_scan_chain(scan_id: int) -> None:
    chain(
        scan_stage_subfinder.s(scan_id),  # type: ignore
        scan_stage_httpx.s(),  # type: ignore
        scan_stage_gau.s(),  # type: ignore
        scan_stage_nuclei.s(),  # type: ignore
    ).apply_async()


@celery_app.task(name="app.tasks.scan_tasks.scan_stage_subfinder")
def scan_stage_subfinder(scan_id: int) -> dict:
    db = get_sessionmaker()()
    try:
        scan, target = _load_scan(scan_id, db)
        if not scan or not target:
            return {"scan_id": scan_id, "subdomains": []}
        _set_stage(scan, db, "subfinder", 1)
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
            _fail_scan(scan, db, stage="subfinder", message=result.error or "subfinder failed")
            raise RuntimeError(result.error or "subfinder failed")

        for host in subdomains:
            db.add(Subdomain(scan_id=scan.id, hostname=host))
        db.commit()
        return {"scan_id": scan.id, "subdomains": subdomains}
    finally:
        db.close()


@celery_app.task(name="app.tasks.scan_tasks.scan_stage_httpx")
def scan_stage_httpx(payload: dict) -> dict:
    db = get_sessionmaker()()
    try:
        scan_id = payload["scan_id"]
        scan, target = _load_scan(scan_id, db)
        if not scan or not target:
            return payload
        _set_stage(scan, db, "httpx", 2)

        subdomains = payload.get("subdomains") or [row.hostname for row in scan.subdomains]
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
            _fail_scan(scan, db, stage="httpx", message=httpx_result.error or "httpx failed")
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
                _append_warning(scan, db, enrich_result.error or "subdomain enrichment failed")
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
        return payload | {"live_hosts": live_hosts}
    finally:
        db.close()


@celery_app.task(name="app.tasks.scan_tasks.scan_stage_gau")
def scan_stage_gau(payload: dict) -> dict:
    db = get_sessionmaker()()
    try:
        scan_id = payload["scan_id"]
        scan, target = _load_scan(scan_id, db)
        if not scan or not target:
            return payload
        _set_stage(scan, db, "gau", 3)

        urls, gau_result = run_gau(target.domain)
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
        asset_rows, derived_endpoints = analyze_javascript_assets(js_candidates, {target.domain} | {row.hostname for row in scan.subdomains})
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
                            {"url": row["url"], "status": row["status"], "secret_count": len(row["secrets_json"])}
                            for row in asset_rows
                        ]
                    },
                },
            )
        else:
            _soft_log(scan, db, "javascript_analysis", {"count": 0, "parsed_json": {"assets": []}})

        if derived_endpoints:
            _upsert_endpoints(db, scan.id, derived_endpoints)
        nuclei_targets = filter_nuclei_targets(normalized + derived_endpoints)
        return payload | {"nuclei_targets": nuclei_targets}
    finally:
        db.close()


@celery_app.task(name="app.tasks.scan_tasks.scan_stage_nuclei")
def scan_stage_nuclei(payload: dict) -> dict:
    db = get_sessionmaker()()
    try:
        scan_id = payload["scan_id"]
        scan, target = _load_scan(scan_id, db)
        if not scan or not target:
            return payload
        _set_stage(scan, db, "nuclei", 4)

        scan_config = scan.scan_config_json or {}
        nuclei_targets = payload.get("nuclei_targets") or []
        vulnerabilities, nuclei_result = run_nuclei(nuclei_targets, scan_config)
        if nuclei_result:
            command_preview = " ".join(shlex.quote(part) for part in nuclei_result.command)
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
                {"count": 0, "scan_config": scan_config, "parsed_json": {"vulnerabilities": []}},
            )
        if nuclei_result and nuclei_result.status != "success":
            _fail_scan(scan, db, stage="nuclei", message=nuclei_result.error or "nuclei failed")
            raise RuntimeError(nuclei_result.error or "nuclei failed")

        _create_vulnerabilities(db, scan.id, vulnerabilities)

        endpoints = db.query(Endpoint).filter(Endpoint.scan_id == scan.id).order_by(Endpoint.priority_score.desc()).all()
        js_assets = db.query(JavaScriptAsset).filter(JavaScriptAsset.scan_id == scan.id).all()
        subdomains = db.query(Subdomain).filter(Subdomain.scan_id == scan.id).all()

        header_findings, headers_result = check_headers([row.url for row in endpoints[: settings.scan_header_probe_cap]])
        if headers_result:
            _log_step(
                db,
                scan.id,
                "header_analysis",
                headers_result.status,
                {"count": len(header_findings), "parsed_json": {"vulnerabilities": header_findings}},
                headers_result,
            )
            if headers_result.status != "success":
                _append_warning(scan, db, headers_result.error or "header analysis failed")
        else:
            _soft_log(scan, db, "header_analysis", {"count": 0, "parsed_json": {"vulnerabilities": []}})

        heuristic_findings = synthesize_heuristic_findings(endpoints, js_assets, subdomains)
        if header_findings:
            heuristic_findings.extend(header_findings)
        _create_vulnerabilities(db, scan.id, heuristic_findings)
        _log_step(
            db,
            scan.id,
            "correlation",
            "success",
            {"count": len(heuristic_findings), "parsed_json": {"vulnerabilities": heuristic_findings[:100]}},
        )

        refreshed_scan, _ = _load_scan(scan.id, db)
        if not refreshed_scan:
            return payload
        ranked_attack_paths = rank_attack_paths(refreshed_scan.endpoints, refreshed_scan.vulnerabilities)
        _create_attack_paths(db, scan.id, ranked_attack_paths)
        _log_step(
            db,
            scan.id,
            "attack_path_generation",
            "success",
            {"count": len(ranked_attack_paths), "parsed_json": {"attack_paths": ranked_attack_paths[:25]}},
        )

        # Detect payload testing opportunities
        try:
            _detect_payload_opportunities(db, scan.id)
            opp_count = db.query(PayloadOpportunity).filter(PayloadOpportunity.scan_id == scan.id).count()
            _log_step(
                db,
                scan.id,
                "payload_opportunity_detection",
                "success",
                {"count": opp_count, "parsed_json": {}},
            )
        except Exception as e:
            _soft_log(scan, db, "payload_opportunity_detection", {"count": 0}, warning=str(e)[:200])

        refreshed_scan, _ = _load_scan(scan.id, db)
        if refreshed_scan:
            _compute_diff_and_notifications(db, refreshed_scan, target)
            metadata = _merge_metadata(
                refreshed_scan,
                stage="completed",
                stage_index=TOTAL_STAGES,
                progress_percent=100,
            )
            _update_scan(refreshed_scan, db, status="completed", metadata_json=metadata)
        return {"scan_id": scan.id, "status": "completed"}
    finally:
        db.close()


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
                .filter(Scan.target_id == schedule.target_id, Scan.status.in_(["pending", "running"]))
                .first()
            )
            if running:
                continue
            scan = Scan(
                target_id=schedule.target_id,
                status="pending",
                metadata_json=_default_metadata("queued", 0) | {"scheduled": True},
                scan_config_json=schedule.scan_config_json or {},
            )
            db.add(scan)
            db.commit()
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
