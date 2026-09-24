"""Environment configuration and startup validation.

Enforces strict validation on all environment variables to ensure secure,
predictable execution in development, testing, and production environments.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional


class ConfigurationError(ValueError):
    """Raised when application environment configuration is invalid."""
    pass


@dataclass
class AppSettings:
    """Validated application settings."""

    # Environment
    app_env: str = "development"
    debug: bool = False

    # Server binding
    api_host: str = "0.0.0.0"
    api_port: int = 8000

    # Resource & Processing Limits
    max_upload_size_mb: int = 50
    max_concurrent_analyses: int = 2
    analysis_timeout_seconds: int = 60
    retention_days: int = 7

    # Storage paths
    data_directory: Path = field(default_factory=lambda: Path("./data"))

    # Engine & Profiles
    default_profile: str = "default"
    default_engine: str = "auto"

    # Security & CORS
    cors_origins: List[str] = field(
        default_factory=lambda: ["http://localhost:5173", "http://localhost:3000"]
    )
    log_level: str = "INFO"

    @classmethod
    def from_env(cls) -> AppSettings:
        """Parse, validate, and return AppSettings from environment variables."""
        env = os.getenv("APP_ENV", "development").strip().lower()
        if env not in {"development", "test", "production"}:
            raise ConfigurationError(
                f"Invalid APP_ENV='{env}'. Allowed values: 'development', 'test', 'production'."
            )

        debug_raw = os.getenv("DEBUG", "false" if env == "production" else "true").strip().lower()
        debug = debug_raw in {"true", "1", "yes"}
        if env == "production" and debug:
            raise ConfigurationError(
                "DEBUG mode cannot be enabled when APP_ENV is 'production'."
            )

        # Port validation
        port_raw = os.getenv("API_PORT", "8000")
        try:
            port = int(port_raw)
            if not (1 <= port <= 65535):
                raise ValueError()
        except ValueError:
            raise ConfigurationError(
                f"Invalid API_PORT='{port_raw}'. Must be an integer between 1 and 65535."
            )

        # Upload size validation
        max_upload_raw = os.getenv("MAX_UPLOAD_SIZE_MB", "50")
        try:
            max_upload = int(max_upload_raw)
            if max_upload <= 0 or max_upload > 500:
                raise ValueError()
        except ValueError:
            raise ConfigurationError(
                f"Invalid MAX_UPLOAD_SIZE_MB='{max_upload_raw}'. Must be between 1 and 500 MB."
            )

        # Concurrency limit validation
        max_concurrency_raw = os.getenv("MAX_CONCURRENT_ANALYSES", "2")
        try:
            max_concurrency = int(max_concurrency_raw)
            if max_concurrency < 1 or max_concurrency > 16:
                raise ValueError()
        except ValueError:
            raise ConfigurationError(
                f"Invalid MAX_CONCURRENT_ANALYSES='{max_concurrency_raw}'. Must be between 1 and 16."
            )

        # Timeout validation
        timeout_raw = os.getenv("ANALYSIS_TIMEOUT_SECONDS", "60")
        try:
            timeout = int(timeout_raw)
            if timeout < 5 or timeout > 600:
                raise ValueError()
        except ValueError:
            raise ConfigurationError(
                f"Invalid ANALYSIS_TIMEOUT_SECONDS='{timeout_raw}'. Must be between 5 and 600 seconds."
            )

        # Retention validation
        retention_raw = os.getenv("RETENTION_DAYS", "7")
        try:
            retention = int(retention_raw)
            if retention < 1 or retention > 365:
                raise ValueError()
        except ValueError:
            raise ConfigurationError(
                f"Invalid RETENTION_DAYS='{retention_raw}'. Must be between 1 and 365 days."
            )

        # Profile validation
        profile = os.getenv("DEFAULT_PROFILE", "default").strip().lower()
        allowed_profiles = {"default", "home_lab", "enterprise", "high_volume"}
        if profile not in allowed_profiles:
            raise ConfigurationError(
                f"Invalid DEFAULT_PROFILE='{profile}'. Allowed: {sorted(list(allowed_profiles))}."
            )

        # Engine validation
        engine = os.getenv("DEFAULT_ENGINE", "auto").strip().lower()
        allowed_engines = {"auto", "native", "scapy", "pyshark"}
        if engine not in allowed_engines:
            raise ConfigurationError(
                f"Invalid DEFAULT_ENGINE='{engine}'. Allowed: {sorted(list(allowed_engines))}."
            )

        # Storage directory
        data_dir = Path(os.getenv("DATA_DIRECTORY", "./data")).resolve()

        # CORS origins validation
        cors_raw = os.getenv(
            "CORS_ORIGINS",
            "http://localhost:5173,http://localhost:3000" if env != "production" else ""
        )
        cors_origins = [o.strip() for o in cors_raw.split(",") if o.strip()]
        if env == "production" and ("*" in cors_origins or not cors_origins):
            raise ConfigurationError(
                "Production environment requires explicit non-wildcard CORS_ORIGINS."
            )

        # Log level validation
        log_level = os.getenv("LOG_LEVEL", "INFO").strip().upper()
        allowed_log_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        if log_level not in allowed_log_levels:
            raise ConfigurationError(
                f"Invalid LOG_LEVEL='{log_level}'. Allowed: {sorted(list(allowed_log_levels))}."
            )

        return cls(
            app_env=env,
            debug=debug,
            api_host=os.getenv("API_HOST", "0.0.0.0"),
            api_port=port,
            max_upload_size_mb=max_upload,
            max_concurrent_analyses=max_concurrency,
            analysis_timeout_seconds=timeout,
            retention_days=retention,
            data_directory=data_dir,
            default_profile=profile,
            default_engine=engine,
            cors_origins=cors_origins,
            log_level=log_level,
        )


# Global singleton instance
settings = AppSettings.from_env()
