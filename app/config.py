from pydantic_settings import BaseSettings, SettingsConfigDict
from pathlib import Path
from dotenv import load_dotenv
import os

ENV_PATH = Path(__file__).resolve().parent.parent / ".env"
load_dotenv(ENV_PATH, override=True)


class Settings(BaseSettings):
    nebius_api_key: str = ""
    nebius_base_url: str = "https://api.tokenfactory.nebius.com/v1/"
    nebius_model: str = "nvidia/nemotron-3-super-120b-a12b"
    promptguard_api_url: str = "http://127.0.0.1:8000"
    promptguard_api_key: str = ""
    cors_allowed_origins: list[str] = [
        "http://localhost:8501",
        "http://127.0.0.1:8501",
    ]
    audit_db_path: str = "audit.db"
    enable_mock_fallback: bool = False
    request_timeout_seconds: float = 30.0

    model_config = SettingsConfigDict(
        env_file=str(ENV_PATH),
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()
