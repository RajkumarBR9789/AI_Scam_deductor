"""
ARQ background worker for asynchronous scan processing.

Run with:  arq worker.WorkerSettings
"""

import json
import logging
from urllib.parse import urlparse

from arq import cron  # noqa: F401 — kept for future scheduled tasks
from arq.connections import RedisSettings
from sqlalchemy import select

from config import settings
from database import AsyncSessionLocal
from models.scan import ScanResult
from services.scan_service import (
    check_phishing_databases,
    compile_red_flags,
    domain_analysis,
    generate_ai_analysis,
    search_fraud_reports,
)

logger = logging.getLogger(__name__)


# ── Helpers ──────────────────────────────────────────────────────────────────

def _arq_redis_settings() -> RedisSettings:
    """Parse REDIS_URL into an ARQ-compatible RedisSettings object."""
    parsed = urlparse(settings.REDIS_URL)
    return RedisSettings(
        host=parsed.hostname or "localhost",
        port=parsed.port or 6379,
        database=int(parsed.path.lstrip("/") or 0),
        password=parsed.password,
    )


# ── Background job ──────────────────────────────────────────────────────────

async def process_scan(ctx: dict, scan_id: str, scan_type: str, input_text: str) -> None:
    """Run the full scan pipeline and persist results.

    Called by ARQ when a background scan is enqueued.
    """
    logger.info("process_scan started", extra={"scan_id": scan_id, "scan_type": scan_type})

    import uuid as _uuid
    _scan_uuid = _uuid.UUID(scan_id) if isinstance(scan_id, str) else scan_id

    async with AsyncSessionLocal() as db:
        # Mark as processing
        result = (await db.execute(select(ScanResult).where(ScanResult.id == _scan_uuid))).scalars().first()
        if not result:
            logger.error("ScanResult %s not found — aborting", scan_id)
            return

        result.status = "processing"
        await db.commit()

        try:
            # 1) Domain analysis
            domain_info = await domain_analysis(input_text)

            # 2) Fraud-report search
            search_results = await search_fraud_reports(input_text, scan_type)

            # 3) Phishing database checks
            phishing_info = await check_phishing_databases(input_text)

            # 4) Score & red flags
            red_flags, risk_score, risk_label = compile_red_flags(
                domain_info, search_results, phishing_info,
                input_text=input_text, scan_type=scan_type,
            )

            # 5) AI analysis
            fraud_mentions = len([
                r for r in search_results
                if any(kw in (r.get("finding", "") + r.get("source", "")).lower()
                       for kw in ("scam", "fraud", "fake", "phishing", "suspicious"))
            ])
            ai_analysis, confidence = await generate_ai_analysis(
                scan_type, input_text, domain_info,
                risk_score, red_flags, fraud_mentions, search_results,
            )

            # 6) Recommendations
            from services.scan_service import _build_recommendations
            recommendations = _build_recommendations(risk_label, scan_type=scan_type)

            # Persist results
            result.risk_score = risk_score
            result.risk_label = risk_label
            result.red_flags = json.dumps(red_flags)
            result.ai_analysis = ai_analysis
            result.confidence = confidence
            result.recommendations = json.dumps(recommendations)
            result.status = "completed"
            await db.commit()
            logger.info("process_scan completed", extra={"scan_id": scan_id, "risk_label": risk_label})

        except Exception:
            result.status = "failed"
            await db.commit()
            logger.exception("process_scan failed for scan_id=%s", scan_id)


# ── ARQ WorkerSettings ──────────────────────────────────────────────────────

class WorkerSettings:
    """Configuration consumed by `arq worker.WorkerSettings`."""
    functions = [process_scan]
    redis_settings = _arq_redis_settings()
    max_jobs = 10
    job_timeout = 300  # 5 minutes
