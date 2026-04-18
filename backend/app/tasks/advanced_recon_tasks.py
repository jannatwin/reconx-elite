"""Celery tasks for advanced reconnaissance features."""

import asyncio
import json
import logging
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.core.database import get_sessionmaker
from app.tasks.celery_app import celery_app
from app.models.advanced_recon import StealthConfig, DiscoveredParameter, FuzzedEndpoint
from app.models.scan import Scan
from app.services.advanced_recon_engine import (
    stealth_scanner,
    parameter_discovery,
    content_fuzzer,
    adaptive_scanner,
)

logger = logging.getLogger(__name__)


@celery_app.task(name="app.tasks.advanced_recon_tasks.parameter_discovery_task")
def parameter_discovery_task(
    user_id: int, target_id: int, endpoint_urls: list, config_id: int = None
) -> dict:
    """Execute parameter discovery task."""
    db = get_sessionmaker()()

    try:
        # Get or create stealth config
        if config_id:
            config = (
                db.query(StealthConfig).filter(StealthConfig.id == config_id).first()
            )
        else:
            # Create default config
            config = StealthConfig(
                target_id=target_id,
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
            db.add(config)
            db.commit()

        # Create a scan record
        scan = Scan(
            target_id=target_id,
            status="running",
            metadata_json={
                "task_type": "parameter_discovery",
                "endpoint_count": len(endpoint_urls),
                "scan_mode": config.scan_mode,
            },
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)

        # Run parameter discovery
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        try:
            results = loop.run_until_complete(
                _run_parameter_discovery(endpoint_urls, config, scan.id)
            )
        finally:
            loop.close()

        # Update scan status
        scan.status = "completed"
        scan.metadata_json.update(
            {
                "completed_at": datetime.now(timezone.utc).isoformat(),
                "parameters_discovered": len(results),
            }
        )
        db.commit()

        logger.info(
            f"Parameter discovery completed for target {target_id}: {len(results)} parameters found"
        )

        return {
            "user_id": user_id,
            "target_id": target_id,
            "scan_id": scan.id,
            "parameters_discovered": len(results),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    except Exception as e:
        logger.error(f"Parameter discovery task failed for target {target_id}: {e}")

        # Update scan status to failed
        if "scan" in locals():
            scan.status = "failed"
            scan.error = str(e)
            db.commit()

        return {
            "user_id": user_id,
            "target_id": target_id,
            "error": str(e),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    finally:
        db.close()


async def _run_parameter_discovery(
    endpoint_urls: list, config: StealthConfig, scan_id: int
) -> list:
    """Run parameter discovery with stealth scanner."""

    discovered_params = []

    async with stealth_scanner(config) as scanner:
        param_discovery = parameter_discovery()

        for url in endpoint_urls:
            try:
                params = await param_discovery.discover_parameters(
                    url, scanner, scan_id
                )
                discovered_params.extend(params)

                # Store in database
                db = get_sessionmaker()()
                try:
                    for param in params:
                        db.add(param)
                    db.commit()
                finally:
                    db.close()

            except Exception as e:
                logger.warning(f"Parameter discovery failed for {url}: {e}")
                continue

    return discovered_params


@celery_app.task(name="app.tasks.advanced_recon_tasks.content_fuzzing_task")
def content_fuzzing_task(
    user_id: int,
    target_id: int,
    base_urls: list,
    wordlist_category: str,
    config_id: int = None,
) -> dict:
    """Execute content fuzzing task."""
    db = get_sessionmaker()()

    try:
        # Get or create stealth config
        if config_id:
            config = (
                db.query(StealthConfig).filter(StealthConfig.id == config_id).first()
            )
        else:
            # Create default config
            config = StealthConfig(
                target_id=target_id,
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
            db.add(config)
            db.commit()

        # Create a scan record
        scan = Scan(
            target_id=target_id,
            status="running",
            metadata_json={
                "task_type": "content_fuzzing",
                "base_url_count": len(base_urls),
                "wordlist_category": wordlist_category,
                "scan_mode": config.scan_mode,
            },
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)

        # Run content fuzzing
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        try:
            results = loop.run_until_complete(
                _run_content_fuzzing(base_urls, wordlist_category, config, scan.id)
            )
        finally:
            loop.close()

        # Update scan status
        scan.status = "completed"
        scan.metadata_json.update(
            {
                "completed_at": datetime.now(timezone.utc).isoformat(),
                "endpoints_discovered": len(results),
            }
        )
        db.commit()

        logger.info(
            f"Content fuzzing completed for target {target_id}: {len(results)} endpoints found"
        )

        return {
            "user_id": user_id,
            "target_id": target_id,
            "scan_id": scan.id,
            "endpoints_discovered": len(results),
            "wordlist_category": wordlist_category,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    except Exception as e:
        logger.error(f"Content fuzzing task failed for target {target_id}: {e}")

        # Update scan status to failed
        if "scan" in locals():
            scan.status = "failed"
            scan.error = str(e)
            db.commit()

        return {
            "user_id": user_id,
            "target_id": target_id,
            "error": str(e),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    finally:
        db.close()


async def _run_content_fuzzing(
    base_urls: list, wordlist_category: str, config: StealthConfig, scan_id: int
) -> list:
    """Run content fuzzing with stealth scanner."""

    discovered_endpoints = []

    async with stealth_scanner(config) as scanner:
        fuzzing_engine = content_fuzzer()

        for url in base_urls:
            try:
                endpoints = await fuzzing_engine.fuzz_content(
                    url, wordlist_category, scanner, scan_id
                )
                discovered_endpoints.extend(endpoints)

                # Store in database
                db = get_sessionmaker()()
                try:
                    for endpoint in endpoints:
                        db.add(endpoint)
                    db.commit()
                finally:
                    db.close()

            except Exception as e:
                logger.warning(f"Content fuzzing failed for {url}: {e}")
                continue

    return discovered_endpoints


@celery_app.task(name="app.tasks.advanced_recon_tasks.adaptive_scan_task")
def adaptive_scan_task(user_id: int, target_id: int, scan_id: int) -> dict:
    """Execute adaptive scanning based on intelligence."""
    db = get_sessionmaker()()

    try:
        # Get scan and endpoints
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return {"error": "Scan not found"}

        from app.models.endpoint import Endpoint

        endpoints = db.query(Endpoint).filter(Endpoint.scan_id == scan_id).all()

        adaptive_results = []

        for endpoint in endpoints:
            try:
                # Analyze endpoint for adaptive recommendations
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)

                try:

                    async def analyze_endpoint():
                        import httpx

                        async with httpx.AsyncClient(timeout=10) as client:
                            response = await client.get(endpoint.url)

                            adaptive = adaptive_scanner()
                            analysis = adaptive.analyze_endpoint(endpoint.url, response)

                            return {
                                "endpoint_url": endpoint.url,
                                "analysis": analysis,
                                "recommendations": analysis.get(
                                    "recommended_techniques", []
                                ),
                                "priority": analysis.get("priority_level", "medium"),
                            }

                    result = loop.run_until_complete(analyze_endpoint())
                    adaptive_results.append(result)

                finally:
                    loop.close()

            except Exception as e:
                logger.warning(f"Adaptive analysis failed for {endpoint.url}: {e}")
                continue

        # Update scan metadata with adaptive results
        scan.metadata_json.update(
            {
                "adaptive_analysis": adaptive_results,
                "adaptive_scan_completed": datetime.now(timezone.utc).isoformat(),
            }
        )
        db.commit()

        return {
            "user_id": user_id,
            "target_id": target_id,
            "scan_id": scan_id,
            "endpoints_analyzed": len(adaptive_results),
            "adaptive_results": adaptive_results,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    except Exception as e:
        logger.error(f"Adaptive scan task failed for scan {scan_id}: {e}")
        return {
            "user_id": user_id,
            "target_id": target_id,
            "scan_id": scan_id,
            "error": str(e),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    finally:
        db.close()
