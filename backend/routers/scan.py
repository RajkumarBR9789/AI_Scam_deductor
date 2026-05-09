"""
FastAPI router for scam-detection scan endpoints.
Prefix: /api/v1/scans
"""

import asyncio
import json
import uuid
import logging
from datetime import date, datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import Response as RawResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from database import get_db
from models.scan import ScanResult
from models.user import User
from schemas.scan import (
    RemainingScans,
    ScanHistoryItem,
    ScanRequest,
    ScanResponse,
)
from services.cache_service import get_cached_scan, set_cached_scan
from services.pdf_service import generate_pdf_report
from services.scan_service import (
    check_phishing_databases,
    compile_red_flags,
    domain_analysis,
    generate_ai_analysis,
    search_fraud_reports,
    _build_recommendations,
)
from services.auth_service import get_current_user
from typing import Optional

router = APIRouter(prefix="/api/v1/scans", tags=["Scans"])
logger = logging.getLogger(__name__)


async def get_optional_user(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> Optional[User]:
    """Return the authenticated user or None for guest (unauthenticated) requests."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    token = auth[len("Bearer "):].strip()
    if not token:
        return None
    try:
        return await get_current_user(token=token, db=db)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _today_scan_count(user_id, db: AsyncSession) -> int:
    """Count scans performed by *user_id* today (UTC)."""
    start_of_day = datetime.combine(date.today(), datetime.min.time()).replace(
        tzinfo=timezone.utc
    )
    result = await db.execute(
        select(func.count())
        .select_from(ScanResult)
        .where(ScanResult.user_id == user_id, ScanResult.created_at >= start_of_day)
    )
    return result.scalar() or 0


# ---------------------------------------------------------------------------
# POST /api/v1/scans/analyze
# ---------------------------------------------------------------------------

@router.post(
    "/analyze",
    response_model=ScanResponse,
    status_code=status.HTTP_200_OK,
    summary="Run a scam-detection scan",
)
async def analyze_scan(
    body: ScanRequest,
    http_request: Request,
    background: bool = False,
    current_user: Optional[User] = Depends(get_optional_user),
    db: AsyncSession = Depends(get_db),
) -> ScanResponse:
    # -- Scan-limit enforcement (authenticated users only) --
    if current_user is not None:
        limit = settings.FREE_DAILY_SCAN_LIMIT
        if current_user.subscription_type == "free":
            if await _today_scan_count(current_user.id, db) >= limit:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Daily scan limit reached. Upgrade to Pro for unlimited scans.",
                )

    # -- Background mode: queue job and return pending record (requires auth) --
    if background:
        if current_user is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Sign in to use background scan mode.",
            )
        arq_pool = getattr(http_request.app.state, "arq_pool", None)
        if not arq_pool:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Background processing unavailable",
            )
        scan_record = ScanResult(
            user_id=current_user.id,
            scan_type=body.scan_type,
            input_text=body.input_text,
            risk_score=0,
            risk_label="PENDING",
            confidence=0.0,
            red_flags="[]",
            ai_analysis="",
            citations="[]",
            recommendations="[]",
            status="pending",
        )
        db.add(scan_record)
        await db.commit()
        await db.refresh(scan_record)
        await arq_pool.enqueue_job(
            "process_scan",
            str(scan_record.id),
            body.scan_type,
            body.input_text,
        )
        return ScanResponse(
            scan_id=scan_record.id,
            input_text=scan_record.input_text,
            scan_type=scan_record.scan_type,
            risk_score=0,
            risk_label="PENDING",
            confidence=0.0,
            red_flags=[],
            ai_analysis="",
            citations=[],
            recommendations=[],
            status="pending",
            created_at=scan_record.created_at,
        )

    # -- Check Redis cache --
    cached = get_cached_scan(body.scan_type, body.input_text)
    if cached:
        logger.info("Cache hit for scan type=%s", body.scan_type)
        # Only persist to DB for authenticated users
        if current_user is not None:
            scan_record = ScanResult(
                user_id=current_user.id,
                scan_type=body.scan_type,
                input_text=body.input_text,
                risk_score=cached["risk_score"],
                risk_label=cached["risk_label"],
                confidence=cached["confidence"],
                red_flags=json.dumps(cached.get("red_flags", [])),
                ai_analysis=cached.get("ai_analysis", ""),
                citations=json.dumps(cached.get("citations", [])),
                recommendations=json.dumps(cached.get("recommendations", [])),
            )
            db.add(scan_record)
            await db.commit()
            await db.refresh(scan_record)
            return ScanResponse(
                scan_id=scan_record.id,
                input_text=scan_record.input_text,
                scan_type=scan_record.scan_type,
                risk_score=cached["risk_score"],
                risk_label=cached["risk_label"],
                confidence=cached["confidence"],
                red_flags=cached.get("red_flags", []),
                ai_analysis=cached.get("ai_analysis", ""),
                citations=cached.get("citations", []),
                recommendations=cached.get("recommendations", []),
                created_at=scan_record.created_at,
            )
        # Guest: return cached result without persisting
        return ScanResponse(
            scan_id=None,
            input_text=body.input_text,
            scan_type=body.scan_type,
            risk_score=cached["risk_score"],
            risk_label=cached["risk_label"],
            confidence=cached["confidence"],
            red_flags=cached.get("red_flags", []),
            ai_analysis=cached.get("ai_analysis", ""),
            citations=cached.get("citations", []),
            recommendations=cached.get("recommendations", []),
            created_at=datetime.now(timezone.utc),
        )

    # -- Run independent I/O steps in parallel --
    is_url = body.input_text.lower().startswith("http")

    async def _empty_dict() -> dict:
        return {}

    async def _no_phishing() -> dict:
        return {"phishtank_flagged": False, "google_safe_browsing_flagged": False}

    domain_task = (
        domain_analysis(body.input_text)
        if body.scan_type in ("website", "seller") and is_url
        else _empty_dict()
    )
    search_task = search_fraud_reports(body.input_text, body.scan_type)
    phishing_task = (
        check_phishing_databases(body.input_text) if is_url
        else _no_phishing()
    )

    domain_info, search_results, phishing_info = await asyncio.gather(
        domain_task, search_task, phishing_task
    )

    # -- Compile red flags & score --
    red_flags, risk_score, risk_label = compile_red_flags(
        domain_info, search_results, phishing_info,
        input_text=body.input_text, scan_type=body.scan_type,
    )

    # -- Count fraud mentions for prompt context --
    fraud_kw = {"scam", "fraud", "fake", "cheat", "phishing", "suspicious", "warning", "avoid"}
    fraud_mentions = sum(
        1
        for r in search_results
        if any(kw in (r.get("finding", "") + r.get("source", "")).lower() for kw in fraud_kw)
    )

    # -- LLM analysis --
    ai_analysis, confidence = await generate_ai_analysis(
        scan_type=body.scan_type,
        input_text=body.input_text,
        domain_info=domain_info,
        risk_score=risk_score,
        red_flags=red_flags,
        fraud_mentions=fraud_mentions,
        search_results=search_results,
    )

    recommendations = _build_recommendations(risk_label, scan_type=body.scan_type)

    # -- Persist (authenticated users only) --
    if current_user is not None:
        scan_record = ScanResult(
            user_id=current_user.id,
            scan_type=body.scan_type,
            input_text=body.input_text,
            risk_score=risk_score,
            risk_label=risk_label,
            confidence=confidence,
            red_flags=json.dumps(red_flags),
            ai_analysis=ai_analysis,
            citations=json.dumps([dict(c) for c in search_results]),
            recommendations=json.dumps(recommendations),
        )
        db.add(scan_record)
        await db.commit()
        await db.refresh(scan_record)
        scan_id = scan_record.id
        created_at = scan_record.created_at
    else:
        scan_id = None
        created_at = datetime.now(timezone.utc)

    # -- Store in Redis cache --
    cache_payload = {
        "risk_score": risk_score,
        "risk_label": risk_label,
        "confidence": confidence,
        "red_flags": red_flags,
        "ai_analysis": ai_analysis,
        "citations": [dict(c) for c in search_results],
        "recommendations": recommendations,
    }
    set_cached_scan(body.scan_type, body.input_text, cache_payload)

    return ScanResponse(
        scan_id=scan_id,
        input_text=body.input_text,
        scan_type=body.scan_type,
        risk_score=risk_score,
        risk_label=risk_label,
        confidence=confidence,
        red_flags=red_flags,
        ai_analysis=ai_analysis,
        citations=search_results,
        recommendations=recommendations,
        created_at=created_at,
    )


# ---------------------------------------------------------------------------
# GET /api/v1/scans/history
# ---------------------------------------------------------------------------

@router.get(
    "/history",
    response_model=list[ScanHistoryItem],
    summary="Fetch recent scan history for the authenticated user",
)
async def get_scan_history(
    limit: int = 10,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(ScanResult)
        .where(ScanResult.user_id == current_user.id)
        .order_by(ScanResult.created_at.desc())
        .limit(min(limit, 50))
    )
    scans = result.scalars().all()
    return [
        ScanHistoryItem(
            scan_id=s.id,
            scan_type=s.scan_type,
            input_text=s.input_text[:50],
            risk_score=s.risk_score,
            risk_label=s.risk_label,
            status=s.status,
            created_at=s.created_at,
        )
        for s in scans
    ]


# ---------------------------------------------------------------------------
# GET /api/v1/scans/remaining
# ---------------------------------------------------------------------------

@router.get(
    "/remaining",
    response_model=RemainingScans,
    summary="Check how many scans the user has left today",
)
async def get_remaining_scans(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    if current_user.subscription_type != "free":
        return RemainingScans(
            remaining=999, limit="unlimited", plan=current_user.subscription_type
        )
    used = await _today_scan_count(current_user.id, db)
    limit = settings.FREE_DAILY_SCAN_LIMIT
    return RemainingScans(
        remaining=max(0, limit - used), limit=limit, plan="free"
    )


# ---------------------------------------------------------------------------
# GET /api/v1/scans/{scan_id}
# ---------------------------------------------------------------------------

@router.get(
    "/{scan_id}",
    response_model=ScanResponse,
    summary="Fetch a single scan by ID",
)
async def get_scan(
    scan_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(ScanResult).where(
            ScanResult.id == scan_id, ScanResult.user_id == current_user.id
        )
    )
    scan = result.scalars().first()
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    return ScanResponse(
        scan_id=scan.id,
        input_text=scan.input_text,
        scan_type=scan.scan_type,
        risk_score=scan.risk_score,
        risk_label=scan.risk_label,
        confidence=scan.confidence,
        red_flags=json.loads(scan.red_flags) if scan.red_flags else [],
        ai_analysis=scan.ai_analysis or "",
        citations=json.loads(scan.citations) if scan.citations else [],
        recommendations=json.loads(scan.recommendations) if scan.recommendations else [],
        created_at=scan.created_at,
    )


# ---------------------------------------------------------------------------
# GET /api/v1/scans/{scan_id}/pdf
# ---------------------------------------------------------------------------

@router.get(
    "/{scan_id}/pdf",
    summary="Download PDF report for a scan",
)
async def get_scan_pdf(
    scan_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(ScanResult).where(
            ScanResult.id == scan_id, ScanResult.user_id == current_user.id
        )
    )
    scan = result.scalars().first()
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    scan_data = {
        "scan_id": str(scan.id),
        "input_text": scan.input_text,
        "scan_type": scan.scan_type,
        "risk_score": scan.risk_score,
        "risk_label": scan.risk_label,
        "confidence": scan.confidence,
        "red_flags": json.loads(scan.red_flags) if scan.red_flags else [],
        "ai_analysis": scan.ai_analysis or "",
        "citations": json.loads(scan.citations) if scan.citations else [],
        "recommendations": json.loads(scan.recommendations) if scan.recommendations else [],
        "created_at": scan.created_at,
    }

    pdf_bytes = generate_pdf_report(scan_data)
    filename = f"scamshield_report_{str(scan_id)[:8]}.pdf"
    return RawResponse(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ---------------------------------------------------------------------------
# GET /api/v1/scans/{scan_id}/status
# ---------------------------------------------------------------------------

@router.get(
    "/{scan_id}/status",
    summary="Check the processing status of a background scan",
)
async def get_scan_status(
    scan_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(ScanResult).where(
            ScanResult.id == scan_id, ScanResult.user_id == current_user.id
        )
    )
    scan = result.scalars().first()
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    return {"scan_id": str(scan.id), "status": scan.status}
