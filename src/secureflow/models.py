from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, field_validator

from secureflow.target_validation import validate_local_target


class ScannerConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    enabled: bool = False
    mode: Literal["passive", "active"] | None = None
    

class ScanProfile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scanners: dict[str, ScannerConfig]


class TargetConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1)
    base_url: HttpUrl
    environment: Literal["local-lab"] = "local-lab"
    source_path: str | None = None

    @field_validator("base_url")
    @classmethod
    def validate_local_target(cls, url: HttpUrl) -> HttpUrl:
        validate_local_target(str(url))
        return url


class ReportingConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    formats: list[Literal["json", "markdown"]] = Field(min_length=1)
    output_dir: str = Field(min_length=1)


class SecureFlowConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    version: Literal[1]
    targets: dict[str, TargetConfig] = Field(min_length=1)
    profiles: dict[str, ScanProfile] = Field(min_length=1)
    reporting: ReportingConfig