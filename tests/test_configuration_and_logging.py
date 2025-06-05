import unittest
import os
import configparser
from AQE.configuration import ConfigurationManager
from AQE.logger import setup_logging, SecurityMetrics
import logging
from io import StringIO
from datetime import datetime # For SecurityMetrics log content checking

# Helper to get a config manager for logger tests
def get_test_config_manager_for_logging(log_timestamps=True, enable_security_metrics_log=True, temp_config_file="test_temp_logging_config.ini"):
    # For logger tests, we often want to ensure the config object has specific settings
    # without necessarily testing the file creation part of ConfigurationManager itself here.
    if os.path.exists(temp_config_file):
        os.remove(temp_config_file)

    # Create a config, save it, then load it to ensure settings are "from file" if needed,
    # or just use it directly if testing in-memory behavior.
    # For these logger tests, direct use after setting is fine.
    config = ConfigurationManager(config_file=temp_config_file)
    # Use a temporary, unique config file for each test setup if they might interfere.
    # The set method of the modified ConfigurationManager does not save if the file didn't exist initially.
    # So, to test loading from a file, we'd need to create the file first.
    # However, setup_logging and SecurityMetrics take the config_manager instance directly.

    # To ensure these settings are in the config object for the logger tests:
    if not config.config.has_section("logging"):
        config.config.add_section("logging")
    config.config.set("logging", "LOG_TIMESTAMPS", str(log_timestamps).lower())
    config.config.set("logging", "ENABLE_SECURITY_METRICS_LOG", str(enable_security_metrics_log).lower())

    # If we needed to simulate loading these from a file for the logger:
    # with open(temp_config_file, 'w') as f:
    #     config.config.write(f)
    # config = ConfigurationManager(config_file=temp_config_file) # then reload
    return config

class TestConfigurationManager(unittest.TestCase):
    def setUp(self):
        self.non_existent_config = "test_files/non_existent_config.ini"
        self.test_config_for_load = "test_files/test_config_for_load.ini"
        self.no_initial_file_set_test = "test_files/no_initial_file_set_test.ini"
        self.initial_file_set_test = "test_files/initial_file_set_test.ini"

        # Ensure directory for test files exists
        os.makedirs("test_files", exist_ok=True)

        # Clean up before each test
        for f_path in [self.non_existent_config, self.test_config_for_load,
                       self.no_initial_file_set_test, self.initial_file_set_test]:
            if os.path.exists(f_path):
                os.remove(f_path)

    def tearDown(self):
        # Clean up after each test
        for f_path in [self.non_existent_config, self.test_config_for_load,
                       self.no_initial_file_set_test, self.initial_file_set_test]:
            if os.path.exists(f_path):
                os.remove(f_path)
        # Attempt to remove the directory if empty
        try:
            os.rmdir("test_files")
        except OSError:
            pass # Directory not empty or other error, fine for teardown

    def test_default_behavior_no_config_file(self):
        config_manager = ConfigurationManager(config_file=self.non_existent_config)
        self.assertFalse(os.path.exists(self.non_existent_config))
        self.assertEqual(config_manager.get("kex", "KEX_ALG"), "Kyber1024")
        self.assertTrue(config_manager.getboolean("logging", "LOG_TIMESTAMPS"))
        self.assertTrue(config_manager.getboolean("logging", "ENABLE_SECURITY_METRICS_LOG"))

    def test_loading_and_updating_existing_config_file(self):
        # Create a temporary test_config.ini
        with open(self.test_config_for_load, "w") as f:
            f.write("[kex]\n")
            f.write("KEX_ALG = SomeOldAlg\n")
            f.write("[timeouts]\n")
            f.write("HANDSHAKE_TIMEOUT = 10\n")

        config_manager = ConfigurationManager(config_file=self.test_config_for_load)

        self.assertEqual(config_manager.get("kex", "KEX_ALG"), "SomeOldAlg")
        self.assertEqual(config_manager.getint("timeouts", "HANDSHAKE_TIMEOUT"), 10)
        self.assertEqual(config_manager.get("signature", "SIG_ALG"), "Dilithium3") # Default added
        self.assertTrue(config_manager.getboolean("logging", "LOG_TIMESTAMPS")) # Default added

        # Verify that test_config.ini was updated on disk
        parser = configparser.ConfigParser(interpolation=None)
        parser.read(self.test_config_for_load)
        self.assertEqual(parser.get("kex", "KEX_ALG"), "SomeOldAlg")
        self.assertEqual(parser.getint("timeouts", "HANDSHAKE_TIMEOUT"), 10)
        self.assertEqual(parser.get("signature", "SIG_ALG"), "Dilithium3")
        self.assertTrue(parser.getboolean("logging", "LOG_TIMESTAMPS"))
        self.assertTrue(parser.getboolean("logging", "ENABLE_SECURITY_METRICS_LOG"))

    def test_set_method_behavior(self):
        # Scenario 1: No initial file
        config_manager_no_file = ConfigurationManager(config_file=self.no_initial_file_set_test)
        config_manager_no_file.set("kex", "KEX_ALG", "NewKyber")
        self.assertFalse(os.path.exists(self.no_initial_file_set_test))
        self.assertEqual(config_manager_no_file.get("kex", "KEX_ALG"), "NewKyber")

        # Scenario 2: With initial file
        with open(self.initial_file_set_test, "w") as f:
            f.write("[logging]\nLOG_TIMESTAMPS = false\n")

        config_manager_with_file = ConfigurationManager(config_file=self.initial_file_set_test)
        self.assertFalse(config_manager_with_file.getboolean("logging", "LOG_TIMESTAMPS")) # Pre-check

        config_manager_with_file.set("kex", "KEX_ALG", "AnotherNewKyber")
        config_manager_with_file.set("logging", "LOG_TIMESTAMPS", "True")

        self.assertTrue(os.path.exists(self.initial_file_set_test))
        self.assertEqual(config_manager_with_file.get("kex", "KEX_ALG"), "AnotherNewKyber")
        self.assertTrue(config_manager_with_file.getboolean("logging", "LOG_TIMESTAMPS"))

        parser = configparser.ConfigParser(interpolation=None)
        parser.read(self.initial_file_set_test)
        self.assertEqual(parser.get("kex", "KEX_ALG"), "AnotherNewKyber")
        self.assertTrue(parser.getboolean("logging", "LOG_TIMESTAMPS"))


class TestLogging(unittest.TestCase):
    def setUp(self):
        self.log_stream = StringIO() # For capturing log output if needed by handlers
        self.test_log_file = "test_files/temp_test_quantum_secure_comm.log"
        self.test_metrics_log_file = "test_files/temp_test_security_metrics.log"
        self.test_temp_config_ini = "test_files/test_temp_logging_config.ini" # Used by get_test_config_manager_for_logging

        os.makedirs("test_files", exist_ok=True)

        for f_path in [self.test_log_file, self.test_metrics_log_file, self.test_temp_config_ini]:
            if os.path.exists(f_path):
                os.remove(f_path)

    def tearDown(self):
        for f_path in [self.test_log_file, self.test_metrics_log_file, self.test_temp_config_ini]:
            if os.path.exists(f_path):
                os.remove(f_path)
        try:
            os.rmdir("test_files")
        except OSError:
            pass

    def test_timestamps_enabled(self):
        config = get_test_config_manager_for_logging(log_timestamps=True, temp_config_file=self.test_temp_config_ini)
        # Ensure the logger uses a unique file for this test run
        logger = setup_logging(config_manager=config, log_level="INFO", log_file=self.test_log_file)

        logger.info("Test message with timestamps.")

        # Ensure handlers are flushed
        for handler in logger.handlers:
            handler.flush()
            handler.close() # Close to ensure content is written
        logger.handlers.clear() # Avoid issues with re-setup if tests are run multiple times in one session

        with open(self.test_log_file, "r") as f:
            log_content = f.read()

        self.assertRegex(log_content, r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3} - AQE - INFO - Test message with timestamps.")

    def test_timestamps_disabled(self):
        config = get_test_config_manager_for_logging(log_timestamps=False, temp_config_file=self.test_temp_config_ini)
        logger = setup_logging(config_manager=config, log_level="INFO", log_file=self.test_log_file)
        logger.info("Test message without timestamps.")

        for handler in logger.handlers:
            handler.flush()
            handler.close()
        logger.handlers.clear()

        with open(self.test_log_file, "r") as f:
            log_content = f.read()

        self.assertRegex(log_content, r"AQE - INFO - Test message without timestamps.")
        self.assertNotRegex(log_content, r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}")

    def test_security_metrics_log_enabled(self):
        config = get_test_config_manager_for_logging(enable_security_metrics_log=True, temp_config_file=self.test_temp_config_ini)
        # The SecurityMetrics __init__ is synchronous regarding file creation.
        metrics = SecurityMetrics(config_manager=config, metrics_log_file=self.test_metrics_log_file)

        self.assertTrue(os.path.exists(self.test_metrics_log_file))
        with open(self.test_metrics_log_file, "r") as f:
            content = f.read()
            # Check if "Metrics log initialized" or "Metrics logging session started" is present
            self.assertTrue("Metrics log initialized" in content or "Metrics logging session started" in content)

        # Test that logging works (optional, as it's async)
        # import asyncio
        # asyncio.run(metrics._log_metric_update("test_metric_enabled", 1))
        # with open(self.test_metrics_log_file, "r") as f:
        #    content = f.read()
        # self.assertIn("test_metric_enabled += 1", content)


    def test_security_metrics_log_disabled(self):
        config = get_test_config_manager_for_logging(enable_security_metrics_log=False, temp_config_file=self.test_temp_config_ini)
        metrics = SecurityMetrics(config_manager=config, metrics_log_file=self.test_metrics_log_file)

        self.assertFalse(os.path.exists(self.test_metrics_log_file))
        # Ensure no error if trying to log when disabled
        # import asyncio
        # try:
        #    asyncio.run(metrics._log_metric_update("test_metric_disabled", 1))
        # except Exception as e:
        #    self.fail(f"_log_metric_update raised an exception when disabled: {e}")


if __name__ == '__main__':
    unittest.main()
