from typing import Any

from pydantic import BaseModel, Field


class EmailInput(BaseModel):
    id: str
    sender: str
    recipient: str
    subject: str
    body: str
    urls: list[str] = Field(default_factory=list)
    attachments: list[Any] = Field(default_factory=list)
    headers: dict[str, Any] = Field(default_factory=dict)


class AnalysisResult(BaseModel):
    email_id: str
    risk_score: int
    verdict: str
    reasons: list[str]
    impersonation: dict[str, Any] | None = None
    campaign_id: str | None = None


class EmployeeInput(BaseModel):
    organization_id: int
    name: str
    role: str | None = None
    official_email: str


class VendorInput(BaseModel):
    organization_id: int
    vendor_name: str
    official_domain: str


class OrganizationInput(BaseModel):
    company_name: str
    official_domain: str
