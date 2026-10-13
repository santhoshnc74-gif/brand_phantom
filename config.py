import os
import re
import logging
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List

class ConfigurationError(Exception):
    """Raised when application configuration fails validation."""
    pass

class SecretStr:
    """
    A string wrapper for sensitive credentials.
    Prevents accidental leakage in logs, print(), __str__, and __repr__.
    """
    def __init__(self, value: Optional[str]):
        self._value = value or ""

    def get_secret_value(self) -> str:
        return self._value

    def __bool__(self) -> bool:
        return bool(self._value.strip())

    def __repr__(self) -> str:
        return "[REDACTED]"

    def __str__(self) -> str:
        return "[REDACTED]"

    def __eq__(self, other) -> bool:
        if isinstance(other, SecretStr):
            return self._value == other._value
        return self._value == other

class RedactingFormatter(logging.Formatter):
    """
    Log formatter that redacts known secret values and common token patterns.
    """
    SENSITIVE_PATTERNS = [
        re.compile(r'(?i)(bearer\s+)[a-zA-Z0-9_\-\.]+'),
        re.compile(r'(?i)(api[_-]?key\s*[=:]\s*)[^\s,;&]+'),
        re.compile(r'(?i)(secret\s*[=:]\s*)[^\s,;&]+'),
        re.compile(r'(?i)(token\s*[=:]\s*)[^\s,;&]+'),
        re.compile(r'(?i)(password\s*[=:]\s*)[^\s,;&]+'),
        re.compile(r'(?i)(cookie\s*[=:]\s*)[^\s,;&]+'),
    ]

    def __init__(self, fmt=None, datefmt=None, secrets_to_redact=None):
        super().__init__(fmt, datefmt)
        self.secrets_to_redact = set(secrets_to_redact or [])

    def format(self, record: logging.LogRecord) -> str:
        original = super().format(record)
        redacted = original

        # Scrub known registered secret strings
        for sec in self.secrets_to_redact:
            if sec and len(sec) > 3:
                redacted = redacted.replace(sec, "[REDACTED]")

        # Scrub regex credential patterns
        for pattern in self.SENSITIVE_PATTERNS:
            redacted = pattern.sub(r'\1[REDACTED]', redacted)

        return redacted

@dataclass
class ConnectorConfig:
    platform: str
    display_name: str
    enabled: bool
    status: str # "active", "disabled_missing_credentials", "mock_sandbox"
    credentials: Dict[str, SecretStr] = field(default_factory=dict)

    def to_public_dict(self) -> Dict[str, Any]:
        """Returns safe public connector summary without any secret credentials."""
        return {
            "platform": self.platform,
            "display_name": self.display_name,
            "enabled": self.enabled,
            "status": self.status
        }

@dataclass
class AppConfig:
    app_name: str = "BrandSentinel"
    app_version: str = "v1.4.2-enterprise"
    environment: str = "development" # "development", "test", "staging", "production"
    secret_key: SecretStr = field(default_factory=lambda: SecretStr("dev-insecure-key-only-change-in-prod-min32chars"))
    credential_encryption_key: SecretStr = field(default_factory=lambda: SecretStr(""))
    database_url: str = "sqlite:///data/brandsentinel.db"
    host: str = "0.0.0.0"
    port: int = 5000
    log_level: str = "INFO"
    connectors: Dict[str, ConnectorConfig] = field(default_factory=dict)

    @classmethod
    def from_env(cls) -> "AppConfig":
        env = os.getenv("APP_ENV", os.getenv("ENVIRONMENT", "development")).lower().strip()
        raw_secret_key = os.getenv("SECRET_KEY", "")
        db_url = os.getenv("DATABASE_URL", "")
        host = os.getenv("HOST", "0.0.0.0")
        raw_port = os.getenv("PORT", "5000")
        log_level = os.getenv("LOG_LEVEL", "INFO").upper()

        try:
            port = int(raw_port)
        except ValueError:
            raise ConfigurationError(f"PORT must be an integer, got '{raw_port}'")

        # Fallback database URL for dev/test
        if not db_url:
            base_dir = os.path.abspath(os.path.dirname(__file__))
            db_url = f"sqlite:///{os.path.join(base_dir, 'data', 'brandsentinel.db')}"

        # Resolve Connector Configurations
        connectors: Dict[str, ConnectorConfig] = {}

        # 1. Instagram
        ig_client_id = os.getenv("INSTAGRAM_CLIENT_ID", "")
        ig_client_secret = os.getenv("INSTAGRAM_CLIENT_SECRET", "")
        ig_enabled = bool(ig_client_id and ig_client_secret)
        connectors["instagram"] = ConnectorConfig(
            platform="instagram",
            display_name="Instagram Graph API",
            enabled=ig_enabled,
            status="active" if ig_enabled else ("mock_sandbox" if env != "production" else "disabled_missing_credentials"),
            credentials={
                "client_id": SecretStr(ig_client_id),
                "client_secret": SecretStr(ig_client_secret)
            }
        )

        # 2. X (Twitter)
        tw_api_key = os.getenv("TWITTER_API_KEY", "")
        tw_bearer = os.getenv("TWITTER_BEARER_TOKEN", "")
        tw_enabled = bool(tw_api_key or tw_bearer)
        connectors["twitter_x"] = ConnectorConfig(
            platform="twitter_x",
            display_name="X (Twitter) API v2",
            enabled=tw_enabled,
            status="active" if tw_enabled else ("mock_sandbox" if env != "production" else "disabled_missing_credentials"),
            credentials={
                "api_key": SecretStr(tw_api_key),
                "bearer_token": SecretStr(tw_bearer)
            }
        )

        # 3. Apple App Store
        apple_key = os.getenv("APPLE_KEY_ID", "")
        apple_private = os.getenv("APPLE_PRIVATE_KEY", "")
        apple_enabled = bool(apple_key and apple_private)
        connectors["apple_app_store"] = ConnectorConfig(
            platform="apple_app_store",
            display_name="Apple App Store Connect",
            enabled=apple_enabled,
            status="active" if apple_enabled else ("mock_sandbox" if env != "production" else "disabled_missing_credentials"),
            credentials={
                "key_id": SecretStr(apple_key),
                "private_key": SecretStr(apple_private)
            }
        )

        # 4. Google Play
        play_sa = os.getenv("GOOGLE_PLAY_SERVICE_ACCOUNT_JSON", "")
        play_enabled = bool(play_sa)
        connectors["google_play"] = ConnectorConfig(
            platform="google_play",
            display_name="Google Play Developer API",
            enabled=play_enabled,
            status="active" if play_enabled else ("mock_sandbox" if env != "production" else "disabled_missing_credentials"),
            credentials={"service_account": SecretStr(play_sa)}
        )

        # 5. TikTok
        tiktok_app_id = os.getenv("TIKTOK_APP_ID", "")
        tiktok_secret = os.getenv("TIKTOK_SECRET", "")
        tiktok_enabled = bool(tiktok_app_id and tiktok_secret)
        connectors["tiktok"] = ConnectorConfig(
            platform="tiktok",
            display_name="TikTok for Business API",
            enabled=tiktok_enabled,
            status="active" if tiktok_enabled else ("mock_sandbox" if env != "production" else "disabled_missing_credentials"),
            credentials={
                "app_id": SecretStr(tiktok_app_id),
                "secret": SecretStr(tiktok_secret)
            }
        )

        # 6. Global Domain Registry Feed
        dns_key = os.getenv("DOMAIN_FEED_API_KEY", "")
        dns_enabled = bool(dns_key)
        connectors["domain_registry"] = ConnectorConfig(
            platform="domain_registry",
            display_name="Global Domain Registry & DNS Feed",
            enabled=dns_enabled,
            status="active" if dns_enabled else ("mock_sandbox" if env != "production" else "disabled_missing_credentials"),
            credentials={"api_key": SecretStr(dns_key)}
        )

        # 7. YouTube Data API v3
        yt_key = os.getenv("YOUTUBE_API_KEY", "")
        yt_enabled = bool(yt_key)
        connectors["youtube"] = ConnectorConfig(
            platform="youtube",
            display_name="YouTube Data API v3",
            enabled=yt_enabled,
            status="active" if yt_enabled else ("mock_sandbox" if env != "production" else "disabled_missing_credentials"),
            credentials={"api_key": SecretStr(yt_key)}
        )

        raw_cred_key = os.getenv("CREDENTIAL_ENCRYPTION_KEY", "")

        if env == "production":
            secret_key_obj = SecretStr(raw_secret_key)
        else:
            secret_key_obj = SecretStr(raw_secret_key if raw_secret_key else "dev-insecure-key-only-change-in-prod-min32chars")

        config = cls(
            environment=env,
            secret_key=secret_key_obj,
            credential_encryption_key=SecretStr(raw_cred_key),
            database_url=db_url,
            host=host,
            port=port,
            log_level=log_level,
            connectors=connectors
        )

        config.validate()
        return config

    def validate(self) -> None:
        """
        Validates configuration.
        Fails safely if required production settings are missing or insecure.
        """
        # Validate Port
        if not (1 <= self.port <= 65535):
            raise ConfigurationError(f"Invalid PORT {self.port}. Must be between 1 and 65535.")

        # Validate Allowed Environments
        valid_envs = {"development", "test", "staging", "production"}
        if self.environment not in valid_envs:
            raise ConfigurationError(
                f"Invalid environment '{self.environment}'. Must be one of: {', '.join(sorted(valid_envs))}."
            )

        # PRODUCTION ENVIRONMENT VALIDATION (Must Fail Safely)
        if self.environment == "production":
            sec_val = self.secret_key.get_secret_value()
            
            # Missing SECRET_KEY in production must fail
            if not sec_val:
                raise ConfigurationError(
                    "Production startup aborted: SECRET_KEY environment variable is required in production."
                )

            # Insecure default or short SECRET_KEY must fail
            if "dev-insecure" in sec_val or "placeholder" in sec_val or len(sec_val) < 32:
                raise ConfigurationError(
                    "Production startup aborted: SECRET_KEY must be a cryptographically strong secret at least 32 characters long."
                )

            # Database URL must be configured for production
            if not self.database_url:
                raise ConfigurationError(
                    "Production startup aborted: DATABASE_URL must be configured."
                )

    def to_public_dict(self) -> Dict[str, Any]:
        """
        Returns ONLY public, non-secret configuration safe for client-side consumption.
        NEVER includes secret_key, database_url, tokens, or private credentials.
        """
        return {
            "app_name": self.app_name,
            "version": self.app_version,
            "environment": self.environment,
            "supported_connectors": [c.to_public_dict() for c in self.connectors.values()]
        }

    def get_registered_secrets(self) -> List[str]:
        """Collects raw secret strings for the log redactor filter."""
        secrets = []
        if self.secret_key.get_secret_value():
            secrets.append(self.secret_key.get_secret_value())
        if self.credential_encryption_key.get_secret_value():
            secrets.append(self.credential_encryption_key.get_secret_value())
        for c in self.connectors.values():
            for s in c.credentials.values():
                val = s.get_secret_value()
                if val:
                    secrets.append(val)
        return secrets

def configure_secure_logging(config: AppConfig) -> None:
    """Configures application logger with sensitive value redacting."""
    root_logger = logging.getLogger()
    level = getattr(logging, config.log_level, logging.INFO)
    root_logger.setLevel(level)

    formatter = RedactingFormatter(
        fmt="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        secrets_to_redact=config.get_registered_secrets()
    )

    # Attach to existing handlers
    if not root_logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(formatter)
        root_logger.addHandler(handler)
    else:
        for handler in root_logger.handlers:
            handler.setFormatter(formatter)
