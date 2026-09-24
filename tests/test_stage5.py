"""Tests for Stage 5: Configuration validation, storage security, retention, and health probes."""

import os
import shutil
import tempfile
import time
import unittest
from pathlib import Path

from pcap_analyzer.settings import AppSettings, ConfigurationError
from pcap_analyzer.storage.manager import AnalysisStorageManager, StorageSecurityError
from pcap_analyzer.api.routes import get_health_data, get_readiness_data


class TestAppSettingsValidation(unittest.TestCase):
    """Test environment configuration parsing and fail-fast validation."""

    def setUp(self):
        # Save original environment
        self.orig_env = dict(os.environ)

    def tearDown(self):
        # Restore environment
        os.environ.clear()
        os.environ.update(self.orig_env)

    def test_default_settings_valid(self):
        os.environ["APP_ENV"] = "development"
        settings = AppSettings.from_env()
        self.assertEqual(settings.app_env, "development")
        self.assertEqual(settings.api_port, 8000)
        self.assertEqual(settings.max_upload_size_mb, 50)
        self.assertEqual(settings.retention_days, 7)

    def test_invalid_app_env_fails(self):
        os.environ["APP_ENV"] = "invalid_env"
        with self.assertRaises(ConfigurationError) as ctx:
            AppSettings.from_env()
        self.assertIn("Invalid APP_ENV", str(ctx.exception))

    def test_debug_in_production_fails(self):
        os.environ["APP_ENV"] = "production"
        os.environ["DEBUG"] = "true"
        with self.assertRaises(ConfigurationError) as ctx:
            AppSettings.from_env()
        self.assertIn("DEBUG mode cannot be enabled", str(ctx.exception))

    def test_invalid_port_fails(self):
        os.environ["API_PORT"] = "99999"
        with self.assertRaises(ConfigurationError) as ctx:
            AppSettings.from_env()
        self.assertIn("Invalid API_PORT", str(ctx.exception))

    def test_negative_upload_size_fails(self):
        os.environ["MAX_UPLOAD_SIZE_MB"] = "-10"
        with self.assertRaises(ConfigurationError) as ctx:
            AppSettings.from_env()
        self.assertIn("Invalid MAX_UPLOAD_SIZE_MB", str(ctx.exception))

    def test_invalid_retention_days_fails(self):
        os.environ["RETENTION_DAYS"] = "0"
        with self.assertRaises(ConfigurationError) as ctx:
            AppSettings.from_env()
        self.assertIn("Invalid RETENTION_DAYS", str(ctx.exception))

    def test_wildcard_cors_in_production_fails(self):
        os.environ["APP_ENV"] = "production"
        os.environ["DEBUG"] = "false"
        os.environ["CORS_ORIGINS"] = "*"
        with self.assertRaises(ConfigurationError) as ctx:
            AppSettings.from_env()
        self.assertIn("Production environment requires explicit non-wildcard CORS_ORIGINS", str(ctx.exception))


class TestAnalysisStorageSecurity(unittest.TestCase):
    """Test filesystem isolation, path traversal prevention, and data retention."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="pcap_test_storage_")
        self.storage = AnalysisStorageManager(Path(self.temp_dir))

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_generate_and_validate_id(self):
        aid = self.storage.generate_analysis_id()
        self.assertTrue(aid.startswith("analysis_"))
        validated = self.storage.validate_analysis_id(aid)
        self.assertEqual(aid, validated)

    def test_path_traversal_rejected(self):
        invalid_ids = [
            "../../../etc/passwd",
            "analysis/../secret",
            "analysis_123\\..\\evil",
            "../analysis_123",
            "analysis;rm -rf /",
            "id with spaces",
            "id/with/slash",
        ]
        for bad_id in invalid_ids:
            with self.subTest(bad_id=bad_id):
                with self.assertRaises(StorageSecurityError):
                    self.storage.validate_analysis_id(bad_id)

    def test_create_and_status_tracking(self):
        sandbox = self.storage.create_analysis_sandbox()
        self.assertTrue(sandbox.directory.exists())

        # Check initial status is queued
        status_data = self.storage.get_status(sandbox.analysis_id)
        self.assertEqual(status_data["status"], "queued")

        # Transition to processing
        self.storage.update_status(sandbox.analysis_id, "processing", details="Dissecting frames")
        status_data = self.storage.get_status(sandbox.analysis_id)
        self.assertEqual(status_data["status"], "processing")

        # Transition to completed
        self.storage.update_status(sandbox.analysis_id, "completed")
        status_data = self.storage.get_status(sandbox.analysis_id)
        self.assertEqual(status_data["status"], "completed")

    def test_data_retention_dry_run_and_purge(self):
        # Create a sandbox
        sandbox = self.storage.create_analysis_sandbox()
        self.storage.update_status(sandbox.analysis_id, "completed")

        # Simulate old directory by modifying ctime/mtime back in time
        old_time = time.time() - (10 * 86400)
        os.utime(sandbox.directory, (old_time, old_time))

        # Dry run should identify it without deleting
        candidates, bytes_freed = self.storage.cleanup_expired(retention_days=7, dry_run=True)
        self.assertIn(sandbox.analysis_id, candidates)
        self.assertTrue(sandbox.directory.exists())

        # Active purge should remove it
        purged, freed = self.storage.cleanup_expired(retention_days=7, dry_run=False)
        self.assertIn(sandbox.analysis_id, purged)
        self.assertFalse(sandbox.directory.exists())


class TestHealthAndReadiness(unittest.TestCase):
    """Test health and readiness probes."""

    def test_health_check_payload(self):
        health = get_health_data()
        self.assertEqual(health["status"], "ok")
        self.assertEqual(health["version"], "0.1.0")
        self.assertIn("environment", health)

    def test_readiness_check_payload(self):
        readiness = get_readiness_data()
        self.assertIn("ready", readiness)
        self.assertIn("checks", readiness)
        self.assertTrue(readiness["checks"]["storage_writable"])
        self.assertTrue(readiness["checks"]["default_profile_loaded"])


if __name__ == "__main__":
    unittest.main()
