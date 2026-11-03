"""Normalized evidence supports additional sources without retaining email content."""
from datetime import datetime
from typing import Literal
from pydantic import BaseModel, Field


class ActivityEvidence(BaseModel):
    source: str
    source_id: str | None = None
    event_type: Literal['account_creation', 'account_verification', 'login', 'security', 'password', 'transaction', 'activity']
    observed_at: datetime
    confidence_score: int = Field(ge=0, le=100)
    source_url: str | None = None
    timestamp_basis: str = 'email_receipt'
    classification_explanation: str = 'Normalized evidence supplied by the source adapter.'


class DiscoveredService(BaseModel):
    service_name: str
    domain: str
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    last_confirmed_login: datetime | None = None
    last_security_event: datetime | None = None
    activity_status: Literal['unknown', 'recent_evidence', 'possibly_dormant'] = 'unknown'
    confidence_score: int = Field(default=0, ge=0, le=100)
    confidence_explanation: str = 'Maximum evidence rule score; heuristic strength, not a probability or proof of account ownership.'
    activity_status_explanation: str = 'No qualifying evidence establishes recent account use.'
    timeline: list[ActivityEvidence] = Field(default_factory=list)


class LocationEvidence(BaseModel):
    value: str
    kind: Literal['profile_declared', 'provider_reported']
    source: str
    source_url: str | None = None
    retrieved_at: datetime
    explanation: str = 'Profile location; not a verified current, home, or login location.'


class PublicAccountReconstruction(BaseModel):
    provider: str
    username: str | None = None
    profile_url: str | None = None
    retrieved_at: datetime
    service: DiscoveredService
    locations: list[LocationEvidence] = Field(default_factory=list)
    last_seen_basis: str | None = None
    last_public_activity: datetime | None = None
    coverage: dict = Field(default_factory=dict)
    ownership_verified: bool = False
    profile_updated_at: datetime | None = None
    source_outcome: Literal['found', 'absent', 'unknown', 'blocked', 'timed_out'] = 'found'
    linked_profiles: list[str] = Field(default_factory=list)
