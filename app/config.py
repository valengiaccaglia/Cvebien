from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    DEBUG: bool = Field(default=False, description="Enable debug mode")
    SERVER_HOST: str = Field(default="0.0.0.0", description="Server host")
    SERVER_PORT: int = Field(default=8000, description="Server port")

    RESEND_API_KEY: str = Field(default="", description="Resend API key")
    NVD_API_KEY: str = Field(default="", description="NVD API key (free at nvd.nist.gov/developers/request-an-api-key)")
    SUPABASE_URL: str = Field(default="", description="Supabase URL")
    SUPABASE_KEY: str = Field(default="", description="Supabase service key")
    DATABASE_URL: str = Field(default="", description="Postgres database URL")
    BASE_URL: str = Field(default="http://localhost:8000", description="Base URL for unsubscribe links")

    class Config:
        env_file = Path(__file__).resolve().parent.parent / ".env"
        env_file_encoding = "utf-8"
        case_sensitive = True


settings = Settings()
