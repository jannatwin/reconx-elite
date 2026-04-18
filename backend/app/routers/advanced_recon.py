"""API endpoints for advanced reconnaissance features."""

import json

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from typing import Dict, List, Optional

from app.core.database import get_db
from app.core.deps import get_current_user
from app.models.user import User
from app.models.target import Target
from app.models.scan import Scan
from app.models.advanced_recon import (
    StealthConfig,
    DiscoveredParameter,
    FuzzedEndpoint,
    SmartWordlist,
)
from app.tasks.advanced_recon_tasks import (
    content_fuzzing_task,
    parameter_discovery_task,
)

router = APIRouter(prefix="/advanced-recon", tags=["advanced-recon"])


class StealthConfigCreate(BaseModel):
    """Model for creating stealth configuration."""

    scan_mode: str = Field(
        "balanced", description="Scan mode: aggressive, balanced, stealth"
    )
    requests_per_second: int = Field(5, description="Requests per second")
    random_delay_min: int = Field(100, description="Minimum random delay in ms")
    random_delay_max: int = Field(500, description="Maximum random delay in ms")
    concurrent_threads: int = Field(2, description="Concurrent threads")
    max_retries: int = Field(3, description="Maximum retries")
    retry_backoff_factor: int = Field(2, description="Retry backoff factor")
    rotate_user_agents: bool = Field(True, description="Rotate user agents")
    custom_user_agents: Optional[List[str]] = Field(
        None, description="Custom user agents"
    )
    use_jitter: bool = Field(True, description="Use jitter")
    jitter_percentage: int = Field(20, description="Jitter percentage")
    respect_robots_txt: bool = Field(True, description="Respect robots.txt")


class StealthConfigUpdate(BaseModel):
    """Model for updating stealth configuration."""

    scan_mode: Optional[str] = Field(
        None, description="Scan mode: aggressive, balanced, stealth"
    )
    requests_per_second: Optional[int] = Field(None, description="Requests per second")
    random_delay_min: Optional[int] = Field(
        None, description="Minimum random delay in ms"
    )
    random_delay_max: Optional[int] = Field(
        None, description="Maximum random delay in ms"
    )
    concurrent_threads: Optional[int] = Field(None, description="Concurrent threads")
    max_retries: Optional[int] = Field(None, description="Maximum retries")
    retry_backoff_factor: Optional[int] = Field(
        None, description="Retry backoff factor"
    )
    rotate_user_agents: Optional[bool] = Field(None, description="Rotate user agents")
    custom_user_agents: Optional[List[str]] = Field(
        None, description="Custom user agents"
    )
    use_jitter: Optional[bool] = Field(None, description="Use jitter")
    jitter_percentage: Optional[int] = Field(None, description="Jitter percentage")
    respect_robots_txt: Optional[bool] = Field(None, description="Respect robots.txt")


class ParameterDiscoveryRequest(BaseModel):
    """Model for parameter discovery request."""

    target_id: int = Field(..., description="Target ID")
    endpoint_urls: List[str] = Field(..., description="Endpoint URLs to test")
    stealth_config: Optional[StealthConfigCreate] = Field(
        None, description="Stealth configuration"
    )


class ContentFuzzingRequest(BaseModel):
    """Model for content fuzzing request."""

    target_id: int = Field(..., description="Target ID")
    base_urls: List[str] = Field(..., description="Base URLs to fuzz")
    wordlist_category: str = Field("admin", description="Wordlist category")
    stealth_config: Optional[StealthConfigCreate] = Field(
        None, description="Stealth configuration"
    )


class SmartWordlistCreate(BaseModel):
    """Model for creating smart wordlist."""

    name: str = Field(..., description="Wordlist name")
    category: str = Field(..., description="Wordlist category")
    description: Optional[str] = Field(None, description="Wordlist description")
    words: List[str] = Field(..., description="Wordlist words")
    is_public: bool = Field(False, description="Share wordlist publicly")


@router.post("/stealth-config/{target_id}")
async def create_stealth_config(
    target_id: int,
    config: StealthConfigCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Create stealth configuration for a target."""

    # Check if user owns the target
    target = (
        db.query(Target)
        .filter(Target.id == target_id, Target.owner_id == current_user.id)
        .first()
    )

    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    # Remove existing config if any
    existing = (
        db.query(StealthConfig).filter(StealthConfig.target_id == target_id).first()
    )

    if existing:
        db.delete(existing)

    # Create new config
    stealth_config = StealthConfig(
        target_id=target_id,
        scan_mode=config.scan_mode,
        requests_per_second=config.requests_per_second,
        random_delay_min=config.random_delay_min,
        random_delay_max=config.random_delay_max,
        concurrent_threads=config.concurrent_threads,
        max_retries=config.max_retries,
        retry_backoff_factor=config.retry_backoff_factor,
        rotate_user_agents=config.rotate_user_agents,
        custom_user_agents=(
            json.dumps(config.custom_user_agents) if config.custom_user_agents else None
        ),
        use_jitter=config.use_jitter,
        jitter_percentage=config.jitter_percentage,
        respect_robots_txt=config.respect_robots_txt,
    )

    db.add(stealth_config)
    db.commit()
    db.refresh(stealth_config)

    return {
        "message": "Stealth configuration created",
        "config_id": stealth_config.id,
        "scan_mode": stealth_config.scan_mode,
    }


@router.get("/stealth-config/{target_id}")
async def get_stealth_config(
    target_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get stealth configuration for a target."""

    # Check if user owns the target
    target = (
        db.query(Target)
        .filter(Target.id == target_id, Target.owner_id == current_user.id)
        .first()
    )

    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    config = (
        db.query(StealthConfig).filter(StealthConfig.target_id == target_id).first()
    )

    if not config:
        # Return default config
        return {
            "scan_mode": "balanced",
            "requests_per_second": 5,
            "random_delay_min": 100,
            "random_delay_max": 500,
            "concurrent_threads": 2,
            "max_retries": 3,
            "retry_backoff_factor": 2,
            "rotate_user_agents": True,
            "custom_user_agents": None,
            "use_jitter": True,
            "jitter_percentage": 20,
            "respect_robots_txt": True,
        }

    return {
        "id": config.id,
        "scan_mode": config.scan_mode,
        "requests_per_second": config.requests_per_second,
        "random_delay_min": config.random_delay_min,
        "random_delay_max": config.random_delay_max,
        "concurrent_threads": config.concurrent_threads,
        "max_retries": config.max_retries,
        "retry_backoff_factor": config.retry_backoff_factor,
        "rotate_user_agents": config.rotate_user_agents,
        "custom_user_agents": (
            json.loads(config.custom_user_agents) if config.custom_user_agents else None
        ),
        "use_jitter": config.use_jitter,
        "jitter_percentage": config.jitter_percentage,
        "respect_robots_txt": config.respect_robots_txt,
        "created_at": config.created_at,
        "updated_at": config.updated_at,
    }


@router.post("/parameter-discovery")
async def discover_parameters(
    request: ParameterDiscoveryRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Start parameter discovery on endpoints."""

    # Check if user owns the target
    target = (
        db.query(Target)
        .filter(Target.id == request.target_id, Target.owner_id == current_user.id)
        .first()
    )

    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    # Create or get stealth config
    if request.stealth_config:
        config = StealthConfig(
            target_id=request.target_id,
            scan_mode=request.stealth_config.scan_mode,
            requests_per_second=request.stealth_config.requests_per_second,
            random_delay_min=request.stealth_config.random_delay_min,
            random_delay_max=request.stealth_config.random_delay_max,
            concurrent_threads=request.stealth_config.concurrent_threads,
            max_retries=request.stealth_config.max_retries,
            retry_backoff_factor=request.stealth_config.retry_backoff_factor,
            rotate_user_agents=request.stealth_config.rotate_user_agents,
            custom_user_agents=(
                json.dumps(request.stealth_config.custom_user_agents)
                if request.stealth_config.custom_user_agents
                else None
            ),
            use_jitter=request.stealth_config.use_jitter,
            jitter_percentage=request.stealth_config.jitter_percentage,
            respect_robots_txt=request.stealth_config.respect_robots_txt,
        )
        db.add(config)
        db.commit()
        config_id = config.id
    else:
        existing = (
            db.query(StealthConfig)
            .filter(StealthConfig.target_id == request.target_id)
            .first()
        )
        config_id = existing.id if existing else None

    parameter_discovery_task.delay(
        current_user.id,
        request.target_id,
        request.endpoint_urls,
        config_id,
    )

    return {
        "message": "Parameter discovery task queued",
        "target_id": request.target_id,
        "endpoint_count": len(request.endpoint_urls),
    }


@router.post("/content-fuzzing")
async def fuzz_content(
    request: ContentFuzzingRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Start content fuzzing on base URLs."""

    # Check if user owns the target
    target = (
        db.query(Target)
        .filter(Target.id == request.target_id, Target.owner_id == current_user.id)
        .first()
    )

    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    # Create or get stealth config
    if request.stealth_config:
        config = StealthConfig(
            target_id=request.target_id,
            scan_mode=request.stealth_config.scan_mode,
            requests_per_second=request.stealth_config.requests_per_second,
            random_delay_min=request.stealth_config.random_delay_min,
            random_delay_max=request.stealth_config.random_delay_max,
            concurrent_threads=request.stealth_config.concurrent_threads,
            max_retries=request.stealth_config.max_retries,
            retry_backoff_factor=request.stealth_config.retry_backoff_factor,
            rotate_user_agents=request.stealth_config.rotate_user_agents,
            custom_user_agents=(
                json.dumps(request.stealth_config.custom_user_agents)
                if request.stealth_config.custom_user_agents
                else None
            ),
            use_jitter=request.stealth_config.use_jitter,
            jitter_percentage=request.stealth_config.jitter_percentage,
            respect_robots_txt=request.stealth_config.respect_robots_txt,
        )
        db.add(config)
        db.commit()
        config_id = config.id
    else:
        existing = (
            db.query(StealthConfig)
            .filter(StealthConfig.target_id == request.target_id)
            .first()
        )
        config_id = existing.id if existing else None

    content_fuzzing_task.delay(
        current_user.id,
        request.target_id,
        request.base_urls,
        request.wordlist_category,
        config_id,
    )

    return {
        "message": "Content fuzzing task queued",
        "target_id": request.target_id,
        "base_url_count": len(request.base_urls),
        "wordlist_category": request.wordlist_category,
    }


@router.get("/parameters/{target_id}")
async def get_discovered_parameters(
    target_id: int,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get discovered parameters for a target."""

    # Check if user owns the target
    target = (
        db.query(Target)
        .filter(Target.id == target_id, Target.owner_id == current_user.id)
        .first()
    )

    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    # Get all scans for the target
    scans = db.query(Scan).filter(Scan.target_id == target_id).all()
    scan_ids = [scan.id for scan in scans]

    if not scan_ids:
        return {"parameters": []}

    # Get discovered parameters
    parameters = (
        db.query(DiscoveredParameter)
        .filter(DiscoveredParameter.scan_id.in_(scan_ids))
        .order_by(DiscoveredParameter.confidence_score.desc())
        .limit(limit)
        .all()
    )

    return {
        "parameters": [
            {
                "id": p.id,
                "parameter_name": p.parameter_name,
                "parameter_type": p.parameter_type,
                "parameter_value": p.parameter_value,
                "discovery_method": p.discovery_method,
                "confidence_score": p.confidence_score,
                "response_indicators": (
                    json.loads(p.response_indicators) if p.response_indicators else []
                ),
                "status_code_change": p.status_code_change,
                "response_length_change": p.response_length_change,
                "reflection_detected": p.reflection_detected,
                "scan_id": p.scan_id,
                "endpoint_id": p.endpoint_id,
                "created_at": p.created_at,
            }
            for p in parameters
        ]
    }


@router.get("/fuzzed-endpoints/{target_id}")
async def get_fuzzed_endpoints(
    target_id: int,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get fuzzed endpoints for a target."""

    # Check if user owns the target
    target = (
        db.query(Target)
        .filter(Target.id == target_id, Target.owner_id == current_user.id)
        .first()
    )

    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    # Get all scans for the target
    scans = db.query(Scan).filter(Scan.target_id == target_id).all()
    scan_ids = [scan.id for scan in scans]

    if not scan_ids:
        return {"endpoints": []}

    # Get fuzzed endpoints
    endpoints = (
        db.query(FuzzedEndpoint)
        .filter(FuzzedEndpoint.scan_id.in_(scan_ids))
        .order_by(
            FuzzedEndpoint.is_interesting.desc(), FuzzedEndpoint.created_at.desc()
        )
        .limit(limit)
        .all()
    )

    return {
        "endpoints": [
            {
                "id": e.id,
                "url": e.url,
                "path": e.path,
                "method": e.method,
                "status_code": e.status_code,
                "response_length": e.response_length,
                "response_time_ms": e.response_time_ms,
                "is_interesting": e.is_interesting,
                "interest_reasons": (
                    json.loads(e.interest_reasons) if e.interest_reasons else []
                ),
                "content_type": e.content_type,
                "server_header": e.server_header,
                "wordlist_used": e.wordlist_used,
                "payload": e.payload,
                "scan_id": e.scan_id,
                "created_at": e.created_at,
            }
            for e in endpoints
        ]
    }


@router.post("/wordlists")
async def create_wordlist(
    wordlist: SmartWordlistCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Create a smart wordlist."""

    smart_wordlist = SmartWordlist(
        user_id=current_user.id,
        name=wordlist.name,
        category=wordlist.category,
        description=wordlist.description,
        words=json.dumps(wordlist.words),
        word_count=len(wordlist.words),
        is_public=wordlist.is_public,
        priority_score=50,
    )

    db.add(smart_wordlist)
    db.commit()
    db.refresh(smart_wordlist)

    return {
        "message": "Wordlist created",
        "wordlist_id": smart_wordlist.id,
        "word_count": smart_wordlist.word_count,
    }


@router.get("/wordlists")
async def get_wordlists(
    category: Optional[str] = None,
    include_public: bool = True,
    limit: int = 50,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get smart wordlists."""

    query = db.query(SmartWordlist).filter(
        SmartWordlist.user_id == current_user.id, SmartWordlist.is_active == True
    )

    if category:
        query = query.filter(SmartWordlist.category == category)

    if include_public:
        public_wordlists = db.query(SmartWordlist).filter(
            SmartWordlist.is_public == True, SmartWordlist.is_active == True
        )
        query = query.union(public_wordlists)

    wordlists = query.order_by(SmartWordlist.priority_score.desc()).limit(limit).all()

    return {
        "wordlists": [
            {
                "id": w.id,
                "name": w.name,
                "category": w.category,
                "description": w.description,
                "word_count": w.word_count,
                "usage_count": w.usage_count,
                "success_count": w.success_count,
                "success_rate": w.success_rate,
                "priority_score": w.priority_score,
                "is_public": w.is_public,
                "created_at": w.created_at,
                "updated_at": w.updated_at,
            }
            for w in wordlists
        ]
    }


@router.get("/scan-modes")
async def get_scan_modes():
    """Get available scan modes with descriptions."""

    return {
        "scan_modes": {
            "aggressive": {
                "description": "Fast scanning with high request rate",
                "requests_per_second": 20,
                "random_delay_min": 50,
                "random_delay_max": 200,
                "concurrent_threads": 5,
            },
            "balanced": {
                "description": "Balanced speed and stealth",
                "requests_per_second": 5,
                "random_delay_min": 100,
                "random_delay_max": 500,
                "concurrent_threads": 2,
            },
            "stealth": {
                "description": "Slow scanning with maximum stealth",
                "requests_per_second": 1,
                "random_delay_min": 500,
                "random_delay_max": 2000,
                "concurrent_threads": 1,
            },
        }
    }
