import os
import unittest
import logging
from config import AppConfig, ConfigurationError, SecretStr, RedactingFormatter

class SecureConfigTestCase(unittest.TestCase):
    def setUp(self):
        # Save original environment to restore in tearDown
        self.original_env = os.environ.copy()

    def tearDown(self):
        # Restore environment variables
        os.environ.clear()
        os.environ.update(self.original_env)

    def test_default_development_config(self):
        os.environ["APP_ENV"] = "development"
        os.environ.pop("SECRET_KEY", None)
        
        config = AppConfig.from_env()
        self.assertEqual(config.environment, "development")
        self.assertIsInstance(config.secret_key, SecretStr)
        # SecretStr redaction check
        self.assertEqual(str(config.secret_key), "[REDACTED]")
        self.assertEqual(repr(config.secret_key), "[REDACTED]")

    def test_missing_required_production_settings_fail_safely(self):
        os.environ["APP_ENV"] = "production"
        os.environ["SECRET_KEY"] = "" # Empty secret key

        with self.assertRaises(ConfigurationError) as cm:
            AppConfig.from_env()
        self.assertIn("SECRET_KEY", str(cm.exception))
        self.assertIn("required", str(cm.exception).lower())

    def test_weak_production_secret_fails_safely(self):
        os.environ["APP_ENV"] = "production"
        os.environ["SECRET_KEY"] = "short-insecure-secret" # < 32 chars

        with self.assertRaises(ConfigurationError) as cm:
            AppConfig.from_env()
        self.assertIn("at least 32 characters", str(cm.exception))

    def test_valid_production_configuration_passes(self):
        os.environ["APP_ENV"] = "production"
        os.environ["SECRET_KEY"] = "9f8e7d6c5b4a3928170123456789abcdef0123456789abcdef0123456789abcdef"
        os.environ["DATABASE_URL"] = "postgresql://user:pass@localhost:5432/brandsentinel"

        config = AppConfig.from_env()
        self.assertEqual(config.environment, "production")
        self.assertEqual(str(config.secret_key), "[REDACTED]")
        self.assertGreater(len(config.secret_key.get_secret_value()), 32)

    def test_missing_optional_connector_settings_disables_connector(self):
        os.environ["APP_ENV"] = "production"
        os.environ["SECRET_KEY"] = "9f8e7d6c5b4a3928170123456789abcdef0123456789abcdef0123456789abcdef"
        os.environ.pop("INSTAGRAM_CLIENT_ID", None)
        os.environ.pop("INSTAGRAM_CLIENT_SECRET", None)

        # Missing optional connector settings must not fail app startup
        config = AppConfig.from_env()
        ig_connector = config.connectors["instagram"]
        self.assertFalse(ig_connector.enabled)
        self.assertEqual(ig_connector.status, "disabled_missing_credentials")

    def test_provided_optional_connector_settings_enables_connector(self):
        os.environ["APP_ENV"] = "production"
        os.environ["SECRET_KEY"] = "9f8e7d6c5b4a3928170123456789abcdef0123456789abcdef0123456789abcdef"
        os.environ["INSTAGRAM_CLIENT_ID"] = "mock_client_id_123"
        os.environ["INSTAGRAM_CLIENT_SECRET"] = "mock_client_secret_xyz"

        config = AppConfig.from_env()
        ig_connector = config.connectors["instagram"]
        self.assertTrue(ig_connector.enabled)
        self.assertEqual(ig_connector.status, "active")

    def test_secret_redaction_in_logs(self):
        sensitive_token = "secret_top_confidential_token_999"
        formatter = RedactingFormatter(
            fmt="%(message)s",
            secrets_to_redact=[sensitive_token]
        )

        record1 = logging.LogRecord(
            name="test", level=logging.INFO, pathname="", lineno=0,
            msg=f"Calling endpoint with key {sensitive_token} successfully", args=(), exc_info=None
        )
        output1 = formatter.format(record1)
        self.assertNotIn(sensitive_token, output1)
        self.assertIn("[REDACTED]", output1)

        # Regex redaction of Bearer token
        record2 = logging.LogRecord(
            name="test", level=logging.INFO, pathname="", lineno=0,
            msg="Header Authorization: Bearer abc123xyz890secretTokenValue", args=(), exc_info=None
        )
        output2 = formatter.format(record2)
        self.assertNotIn("abc123xyz890secretTokenValue", output2)
        self.assertIn("Bearer [REDACTED]", output2)

    def test_public_config_separation(self):
        os.environ["SECRET_KEY"] = "9f8e7d6c5b4a3928170123456789abcdef0123456789abcdef0123456789abcdef"
        os.environ["INSTAGRAM_CLIENT_ID"] = "mock_id"
        os.environ["INSTAGRAM_CLIENT_SECRET"] = "mock_secret"

        config = AppConfig.from_env()
        public_dict = config.to_public_dict()

        # Public fields present
        self.assertIn("app_name", public_dict)
        self.assertIn("version", public_dict)
        self.assertIn("environment", public_dict)
        self.assertIn("supported_connectors", public_dict)

        # Server secrets strictly ABSENT
        self.assertNotIn("secret_key", public_dict)
        self.assertNotIn("database_url", public_dict)
        for conn in public_dict["supported_connectors"]:
            self.assertNotIn("credentials", conn)
            self.assertNotIn("client_secret", conn)
            self.assertIn("platform", conn)
            self.assertIn("enabled", conn)

    def test_invalid_port_fails_validation(self):
        os.environ["PORT"] = "99999" # Out of range
        with self.assertRaises(ConfigurationError) as cm:
            AppConfig.from_env()
        self.assertIn("PORT", str(cm.exception))

    def test_invalid_environment_fails_validation(self):
        os.environ["APP_ENV"] = "invalid_environment_value"
        with self.assertRaises(ConfigurationError) as cm:
            AppConfig.from_env()
        self.assertIn("environment", str(cm.exception).lower())

if __name__ == "__main__":
    unittest.main()
