"""
Unit tests for Config class
"""

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pyasn.core.config import Config
from pyasn.core.exceptions import ConfigurationError

class TestConfig(unittest.TestCase):
    """Test Config class"""
    
    def setUp(self):
        """Set up for tests"""
        # Create temp directory for tests
        self.temp_dir = Path(tempfile.mkdtemp())
        
        # Create test config file
        self.config_file = self.temp_dir / "config.yaml"
        with open(self.config_file, 'w') as f:
            f.write("""
            debug: true
            monochrome: true
            mtr_rounds: 10
            ipinfo_token: 'test_token'
            """)
    
    def tearDown(self):
        """Clean up after tests"""
        # Remove temp directory and test files
        import shutil
        shutil.rmtree(self.temp_dir)
    
    def test_default_config(self):
        """Test default configuration"""
        config = Config()
        
        # Check default values
        self.assertFalse(config.debug)
        self.assertFalse(config.monochrome)
        self.assertTrue(config.mtr_tracing)
        self.assertEqual(config.mtr_rounds, 5)
        self.assertIsNone(config.ipinfo_token)
    
    def test_load_config_file(self):
        """Test loading config from file"""
        config = Config(self.config_file)
        
        # Check values from config file
        self.assertTrue(config.debug)
        self.assertTrue(config.monochrome)
        self.assertEqual(config.mtr_rounds, 10)
        self.assertEqual(config.ipinfo_token, 'test_token')
    
    def test_load_nonexistent_config_file(self):
        """Test loading nonexistent config file raises exception"""
        nonexistent_file = self.temp_dir / "nonexistent.yaml"
        
        with self.assertRaises(ConfigurationError):
            Config(nonexistent_file)
    
    @patch.dict(os.environ, {"PYASN_DEBUG": "1", "PYASN_MONOCHROME": "true", "PYASN_IPINFO_TOKEN": "env_token"})
    def test_load_environment_vars(self):
        """Test loading config from environment variables"""
        config = Config()
        
        # Check values from environment variables
        self.assertTrue(config.debug)
        self.assertTrue(config.monochrome)
        self.assertEqual(config.ipinfo_token, 'env_token')
    
    def test_validate_configuration(self):
        """Test configuration validation"""
        # Create invalid config file
        invalid_config_file = self.temp_dir / "invalid_config.yaml"
        with open(invalid_config_file, 'w') as f:
            f.write("""
            mtr_rounds: -5
            """)
        
        with self.assertRaises(ConfigurationError):
            Config(invalid_config_file)
    
    def test_save_config(self):
        """Test saving configuration to file"""
        config = Config()
        config.debug = True
        config.ipinfo_token = "new_token"
        
        # Save to temp file
        save_file = self.temp_dir / "saved_config.yaml"
        config.save(save_file)
        
        # Load the saved config to verify
        loaded_config = Config(save_file)
        
        self.assertTrue(loaded_config.debug)
        self.assertEqual(loaded_config.ipinfo_token, "new_token")

if __name__ == "__main__":
    unittest.main()