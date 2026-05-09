"""
Pydantic v2 schemas for scam-scan request / response payloads.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Request
# ---------------------------------------------------------------------------

class ScanRequest(BaseModel):
    """Payload for POST /api/v1/scans/analyze."""

    input_text: str = Field(..., min_length=1, max_length=2000)
    scan_type: str = Field(
        ...,
        pattern=r"^(website|job|profile|seller|email_phone|upi|sms|qr_code)$",
        description="One of: website, job, profile, seller, email_phone, upi, sms, qr_code",
    )


# ---------------------------------------------------------------------------
# Response
# ---------------------------------------------------------------------------

class CitationItem(BaseModel):
    source: str
    finding: str
    url: str


class ScanResponse(BaseModel):
    """Full result returned after a scan completes."""

    scan_id: uuid.UUID | None = None
    input_text: str
    scan_type: str
    risk_score: int = Field(..., ge=0, le=100)
    risk_label: str
    confidence: float = Field(..., ge=0, le=100)
    red_flags: list[str]
    ai_analysis: str
    citations: list[CitationItem]
    recommendations: list[str]
    status: str = "completed"
    created_at: datetime

    model_config = {"from_attributes": True}


class ScanHistoryItem(BaseModel):
    scan_id: uuid.UUID
    scan_type: str
    input_text: str
    risk_score: int
    risk_label: str
    status: str = "completed"
    created_at: datetime


class RemainingScans(BaseModel):
    remaining: int
    limit: int | str
    plan: str
