from pathlib import Path

import yaml
from pydantic import ValidationError

from secureflow.models import SecureFlowConfig


def load_config(config_path: str) -> SecureFlowConfig:
    path = Path(config_path)

    if not path.is_file():
        raise FileNotFoundError(
            f"Configuration file not found: {path}"
        )

    with path.open("r", encoding="utf-8") as file:
        data = yaml.safe_load(file)

    if not isinstance(data, dict):
        raise ValueError(
            "Configuration must contain a YAML mapping."
        )

    try:
        return SecureFlowConfig.model_validate(data)
    except ValidationError as error:
        raise ValueError(
            f"Invalid SecureFlow configuration:\n{error}"
        ) from error
