from __future__ import annotations

from collections import defaultdict
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session, selectinload

from app.core.config import settings
from app.core.database import get_db
from app.core.deps import get_current_user, require_admin
from app.models.scan import Scan
from app.models.target import Target
from app.models.user import User
from app.models.vulnerability import Vulnerability
from app.schemas.verification import (
    AgentLogEventOut,
    AgentLogHistoryResponse,
    ChainAnalysisRequest,
    ChainAnalysisResponse,
    FindingsResponse,
    HostGroupState,
    HostTriageRequest,
    HostTriageResponse,
    JavaScriptAnalysisRequest,
    JavaScriptAnalysisResponse,
    JavaScriptAnalysisState,
    ModelStatusResponse,
    PayloadGenerationRequest,
    PayloadGenerationResponse,
    ReportWriteRequest,
    ReportWriteResponse,
    SeverityRequest,
    SeverityResponse,
    VerificationFinding,
    VerificationState,
)
from app.services.ai_service import (
    analyze_finding_chains,
    analyze_js_content,
    generate_payloads,
    get_model_status_snapshot,
    rate_finding_severity,
    triage_hosts,
    verify_all_models,
    write_finding_report,
)
from app.services.websocket import get_recent_agent_log_events

router = APIRouter(prefix="/api", tags=["verification-api"])


def _ensure_target_access(target: Target | None, current_user: User) -> Target:
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    if current_user.role != "admin" and target.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Access denied")
    return target


def _load_target_and_scan(
    db: Session,
    current_user: User,
    target_id: int,
    scan_id: int | None = None,
) -> tuple[Target, Scan | None]:
    target = db.query(Target).filter(Target.id == target_id).first()
    target = _ensure_target_access(target, current_user)
    scan_query = (
        db.query(Scan)
        .options(
            selectinload(Scan.subdomains),
            selectinload(Scan.endpoints),
            selectinload(Scan.javascript_assets),
            selectinload(Scan.attack_paths),
            selectinload(Scan.logs),
            selectinload(Scan.vulnerabilities).selectinload(Vulnerability.ai_report),
            selectinload(Scan.vulnerabilities).selectinload(Vulnerability.validation),
        )
        .filter(Scan.target_id == target.id)
    )
    if scan_id is not None:
        scan = scan_query.filter(Scan.id == scan_id).first()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        return target, scan
    scan = scan_query.order_by(Scan.created_at.desc()).first()
    return target, scan


def _flatten_agent_event(event: dict[str, Any]) -> dict[str, Any]:
    payload = dict(event.get("data") or {})
    return {
        "type": event.get("type"),
        "event": payload.get("event"),
        "timestamp": event.get("timestamp") or payload.get("timestamp"),
        "role": payload.get("role"),
        "model_id": payload.get("model_id"),
        "task": payload.get("task"),
        "status": payload.get("status"),
        "success": payload.get("success"),
        "tokens_used": payload.get("tokens_used"),
        "message": payload.get("message"),
        "error": payload.get("error"),
        "origin_process": payload.get("origin_process"),
    }


def _infer_finding_type(vulnerability: Vulnerability) -> str:
    candidate = f"{vulnerability.template_id} {vulnerability.description or ''}".lower()
    if "idor" in candidate:
        return "IDOR"
    if "xss" in candidate:
        return "XSS"
    if "sql" in candidate:
        return "SQLi"
    if "ssrf" in candidate:
        return "SSRF"
    if "takeover" in candidate:
        return "Takeover"
    if "cors" in candidate:
        return "CORS"
    return vulnerability.template_id or "Finding"


def _finding_status(vulnerability: Vulnerability) -> str:
    if vulnerability.ai_report:
        return "reported"
    if any(
        (row.validation_status or "").lower() == "confirmed"
        for row in vulnerability.validation
    ):
        return "confirmed"
    return "unconfirmed"


def _build_findings(scan: Scan | None) -> list[VerificationFinding]:
    if not scan:
        return []
    by_endpoint: dict[str, list[str]] = defaultdict(list)
    for vulnerability in scan.vulnerabilities:
        endpoint = vulnerability.matched_url or vulnerability.host or ""
        by_endpoint[endpoint].append(str(vulnerability.id))

    findings: list[VerificationFinding] = []
    for vulnerability in scan.vulnerabilities:
        ai_report = vulnerability.ai_report[0] if vulnerability.ai_report else None
        validation = vulnerability.validation[0] if vulnerability.validation else None
        severity = (vulnerability.severity or "medium").title()
        cvss_score = 0.0
        cvss_vector = ""
        if ai_report and ai_report.cvss_score:
            try:
                cvss_score = float(ai_report.cvss_score)
            except (TypeError, ValueError):
                cvss_score = 0.0
        endpoint = vulnerability.matched_url or vulnerability.host or ""
        parameter = ""
        matched_params = (
            (vulnerability.evidence_json or {}).get("matched_params")
            if vulnerability.evidence_json
            else None
        )
        if isinstance(matched_params, list) and matched_params:
            parameter = str(matched_params[0])
        reproduction_steps = []
        if ai_report and ai_report.proof_of_concept:
            reproduction_steps = [
                step.strip()
                for step in ai_report.proof_of_concept.splitlines()
                if step.strip()
            ]
        elif validation and validation.url:
            reproduction_steps = [f"Replay request against {validation.url}"]
        chain_with = [
            value
            for value in by_endpoint.get(endpoint, [])
            if value != str(vulnerability.id)
        ]
        findings.append(
            VerificationFinding(
                id=str(vulnerability.id),
                type=_infer_finding_type(vulnerability),
                endpoint=endpoint,
                parameter=parameter,
                payload_used=(
                    validation.payload if validation and validation.payload else ""
                )
                or (
                    ai_report.exploit_draft
                    if ai_report and ai_report.exploit_draft
                    else ""
                ),
                severity=severity,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                description=vulnerability.description
                or (ai_report.summary if ai_report else ""),
                reproduction_steps=reproduction_steps,
                raw_request=(
                    validation.full_request
                    if validation and validation.full_request
                    else ""
                ),
                impact=(
                    ai_report.business_impact
                    if ai_report and ai_report.business_impact
                    else ""
                ),
                remediation=(
                    ai_report.remediation_steps
                    if ai_report and ai_report.remediation_steps
                    else ""
                ),
                chain_with=chain_with,
                status=_finding_status(vulnerability),
                details={
                    "template_id": vulnerability.template_id,
                    "source": vulnerability.source,
                    "confidence": vulnerability.confidence,
                },
            )
        )
    return findings


def _build_host_groups(scan: Scan | None) -> HostGroupState:
    if not scan:
        return HostGroupState()
    grouped: dict[str, list[str]] = defaultdict(list)
    for row in triage_hosts([subdomain.hostname for subdomain in scan.subdomains]):
        grouped[row["classification"]].append(row["host"])
    return HostGroupState(
        total_discovered=len(scan.subdomains),
        live=len([item for item in scan.subdomains if item.is_live]),
        auth_targets=grouped["auth_target"],
        api_targets=grouped["api_target"],
        admin_targets=grouped["admin_target"],
        dev_targets=grouped["dev_target"],
        skip=grouped["skip"],
    )


def _build_js_analysis(scan: Scan | None) -> JavaScriptAnalysisState:
    if not scan:
        return JavaScriptAnalysisState()
    endpoints: list[str] = []
    secrets: list[dict[str, Any]] = []
    for asset in scan.javascript_assets:
        endpoints.extend(asset.extracted_endpoints or [])
        secrets.extend(asset.secrets_json or [])
    unique_endpoints = list(dict.fromkeys(endpoints))
    return JavaScriptAnalysisState(
        files_analyzed=len(scan.javascript_assets),
        endpoints_found=unique_endpoints,
        secrets_found=secrets,
        escalate_immediately=bool(secrets),
    )


def _build_chains(
    scan: Scan | None, findings: list[VerificationFinding]
) -> list[dict[str, Any]]:
    if scan and scan.attack_paths:
        return [
            {
                "id": path.id,
                "title": path.title,
                "combined_severity": path.severity.title(),
                "score": path.score,
                "nodes": path.steps_json or [],
            }
            for path in scan.attack_paths
        ]
    return analyze_finding_chains([finding.model_dump() for finding in findings]).get(
        "chains", []
    )


def _next_action(scan: Scan | None) -> str:
    if not scan:
        return "Create a target and run a scan to initialize verification state."
    if scan.status == "failed":
        return "Investigate blockers, resolve failed phases, and rerun verification."
    if scan.status in {"pending", "running"}:
        return "Wait for the active phase to complete, then review findings and chain opportunities."
    return "Review confirmed findings, validate impact, and draft final reports."


@router.get("/state", response_model=VerificationState)
async def get_verification_state(
    target_id: int = Query(...),
    scan_id: int | None = Query(default=None),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    target, scan = _load_target_and_scan(db, current_user, target_id, scan_id)
    findings = _build_findings(scan)
    js_state = _build_js_analysis(scan)
    escalations: list[str] = []
    if js_state.secrets_found:
        escalations.append("JavaScript secrets found - escalate immediately.")
    if any(finding.severity in {"Critical", "High"} for finding in findings):
        escalations.append(
            "High-severity findings require manual confirmation and reporting review."
        )
    blockers = []
    if scan and scan.error:
        blockers.append(scan.error)
    if scan and scan.metadata_json:
        blockers.extend([str(item) for item in scan.metadata_json.get("errors") or []])
    scan_mode = "passive"
    if scan and scan.scan_config_json:
        scan_mode = scan.scan_config_json.get("profile") or settings.default_scan_mode
    current_phase = "recon"
    if scan and scan.metadata_json:
        current_phase = scan.metadata_json.get("stage") or current_phase
    elif scan:
        current_phase = scan.status

    return VerificationState(
        session_id=f"target-{target.id}-scan-{scan.id if scan else 'none'}",
        target=target.domain,
        wildcard=f"*.{target.domain}",
        scope=[target.domain, f"*.{target.domain}"],
        out_of_scope=[],
        scan_mode=scan_mode,
        current_phase=current_phase,
        hosts=_build_host_groups(scan),
        js_analysis=js_state,
        findings=findings,
        chains_identified=_build_chains(scan, findings),
        reports_drafted=sum(
            len(vulnerability.ai_report)
            for vulnerability in (scan.vulnerabilities if scan else [])
        ),
        model_call_log=[
            AgentLogEventOut(**_flatten_agent_event(event))
            for event in get_recent_agent_log_events(100)
        ],
        next_action=_next_action(scan),
        blockers=blockers,
        escalations=escalations,
    )


@router.get("/findings", response_model=FindingsResponse)
async def get_verification_findings(
    target_id: int = Query(...),
    scan_id: int | None = Query(default=None),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    _, scan = _load_target_and_scan(db, current_user, target_id, scan_id)
    findings = [
        finding
        for finding in _build_findings(scan)
        if finding.status in {"confirmed", "reported"}
    ]
    return FindingsResponse(findings=findings)


@router.get("/agent-log", response_model=AgentLogHistoryResponse)
async def get_agent_log_history(
    limit: int = Query(default=100, ge=1, le=250),
    current_user: User = Depends(require_admin),
):
    return AgentLogHistoryResponse(
        events=[
            AgentLogEventOut(**_flatten_agent_event(event))
            for event in get_recent_agent_log_events(limit)
        ]
    )


@router.post("/triage", response_model=HostTriageResponse)
async def triage_hosts_api(
    payload: HostTriageRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if payload.target_id is not None:
        target = db.query(Target).filter(Target.id == payload.target_id).first()
        _ensure_target_access(target, current_user)
    return HostTriageResponse(classifications=triage_hosts(payload.hosts))


@router.post("/analyze-js", response_model=JavaScriptAnalysisResponse)
async def analyze_js_api(
    payload: JavaScriptAnalysisRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if payload.target_id is not None:
        target = db.query(Target).filter(Target.id == payload.target_id).first()
        _ensure_target_access(target, current_user)
    result = await analyze_js_content(payload.js_content, payload.source_url)
    return JavaScriptAnalysisResponse(**result)


@router.post("/generate-payload", response_model=PayloadGenerationResponse)
async def generate_payload_api(
    payload: PayloadGenerationRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if payload.target_id is not None:
        target = db.query(Target).filter(Target.id == payload.target_id).first()
        _ensure_target_access(target, current_user)
    result = await generate_payloads(payload.vuln_type, payload.context)
    return PayloadGenerationResponse(**result)


@router.post("/rate-severity", response_model=SeverityResponse)
async def rate_severity_api(
    payload: SeverityRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if payload.target_id is not None:
        target = db.query(Target).filter(Target.id == payload.target_id).first()
        _ensure_target_access(target, current_user)
    return SeverityResponse(**rate_finding_severity(payload.finding))


@router.post("/chain-analysis", response_model=ChainAnalysisResponse)
async def chain_analysis_api(
    payload: ChainAnalysisRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if payload.target_id is not None:
        target = db.query(Target).filter(Target.id == payload.target_id).first()
        _ensure_target_access(target, current_user)
    return ChainAnalysisResponse(**analyze_finding_chains(payload.findings))


@router.post("/write-report", response_model=ReportWriteResponse)
async def write_report_api(
    payload: ReportWriteRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if payload.target_id is not None:
        target = db.query(Target).filter(Target.id == payload.target_id).first()
        _ensure_target_access(target, current_user)
    return ReportWriteResponse(
        **(await write_finding_report(payload.finding, payload.severity))
    )


@router.get("/model-status", response_model=ModelStatusResponse)
async def model_status_api(current_user: User = Depends(require_admin)):
    return ModelStatusResponse(**get_model_status_snapshot())


@router.post("/verify-models")
async def verify_models_api(current_user: User = Depends(require_admin)):
    return await verify_all_models()
