from typing import Literal

from pydantic import BaseModel, Field

Severity = Literal["critical", "high", "medium", "low", "info", "unknown"]


class SecurityFinding(BaseModel):
    scanner: str = Field(min_length=1)
    title: str = Field(min_length=1)
    severity: Severity
    description: str = ""
    location: str | None = None
    rule_id: str | None = None
    reference: str | None = None
