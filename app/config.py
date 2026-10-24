from pydantic_settings import BaseSettings, SettingsConfigDict
import os


class Settings(BaseSettings):
    nebius_api_key: str = os.getenv("NEBIUS_API_KEY", "replace_with_your_key")
    nebius_base_url: str = os.getenv("NEBIUS_BASE_URL", "https://api.tokenfactory.nebius.com/v1/")
    nebius_model: str = os.getenv("NEBIUS_MODEL", "nvidia/nemotron-3-super-120b-a12b")
    promptguard_api_url: str = os.getenv("PROMPTGUARD_API_URL", "http://127.0.0.1:8000")
    audit_db_path: str = "audit.db"
    enable_mock_fallback: bool = True  # Allows safe fallback simulation for local testing/demo if Nebius key is placeholder or network offline
    request_timeout_seconds: float = 30.0

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")


settings = Settings()
