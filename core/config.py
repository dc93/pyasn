"""
Configuration management for PyASN
"""

import logging
import os
import tempfile
from pathlib import Path
from typing import Dict, Optional, Any, List

import yaml

from pyasn.core.exceptions import ConfigurationError

class Config:
    """Configuration management for PyASN"""
    
    def __init__(self, config_file: Optional[Path] = None, debug: bool = False):
        """
        Initialize configuration with optional config file
        
        Args:
            config_file: Path to configuration file (YAML)
            debug: Enable debug mode
        """
        self.debug = debug
        
        # Default settings
        self._initialize_defaults()
        
        # Load configuration file if provided
        if config_file:
            self._load_config_file(config_file)
        
        # Load environment variables
        self._load_environment()
        
        # Create necessary directories
        self._ensure_directories()
        
        # Validate configuration
        self._validate_configuration()
    
    def _initialize_defaults(self):
        """Initialize default configuration values"""
        # General settings
        self.monochrome = False
        self.json_output = False
        self.json_pretty = False
        
        # Feature settings
        self.mtr_tracing = True
        self.detailed_trace = False
        self.additional_inetnum_lookup = True
        self.mtr_rounds = 5
        self.max_concurrent_shodan_requests = 10
        self.shodan_show_top_n = 5
        self.iqs_always_query = False
        self.iqs_custom_settings = ""
        
        # API tokens
        self.iqs_token = None
        self.ipinfo_token = None
        self.cloudflare_token = None
        
        # Server settings
        self.default_server_bind_addr_v4 = "127.0.0.1"
        self.default_server_bind_addr_v6 = "::1"
        self.default_server_bind_port = 49200
        
        # Paths and directories
        self.config_dir = Path.home() / ".pyasn"
        self.cache_dir = Path(tempfile.gettempdir()) / "pyasn"
        self.log_file = self.config_dir / "pyasn_debug.log"
    
    def _load_config_file(self, config_file: Path):
        """
        Load configuration from YAML file
        
        Args:
            config_file: Path to configuration file
            
        Raises:
            ConfigurationError: If the file cannot be read or parsed
        """
        try:
            if not config_file.exists():
                raise ConfigurationError(f"Configuration file not found: {config_file}")
            
            with open(config_file, 'r') as f:
                config_data = yaml.safe_load(f)
            
            if not isinstance(config_data, dict):
                raise ConfigurationError("Configuration file must contain a YAML dictionary")
            
            # Update configuration with file values
            self._update_from_dict(config_data)
            
        except Exception as e:
            if isinstance(e, ConfigurationError):
                raise
            raise ConfigurationError(f"Error loading configuration file: {e}")
    
    def _load_environment(self):
        """Load configuration from environment variables"""
        # API tokens
        self.iqs_token = os.environ.get("PYASN_IQS_TOKEN", self.iqs_token)
        self.ipinfo_token = os.environ.get("PYASN_IPINFO_TOKEN", self.ipinfo_token)
        self.cloudflare_token = os.environ.get("PYASN_CLOUDFLARE_TOKEN", self.cloudflare_token)
        
        # Boolean settings
        if os.environ.get("PYASN_DEBUG") in ("1", "true", "yes"):
            self.debug = True
        if os.environ.get("PYASN_MONOCHROME") in ("1", "true", "yes"):
            self.monochrome = True
        if os.environ.get("PYASN_JSON") in ("1", "true", "yes"):
            self.json_output = True
        if os.environ.get("PYASN_JSON_PRETTY") in ("1", "true", "yes"):
            self.json_pretty = True
    
    def _ensure_directories(self):
        """Ensure required directories exist"""
        try:
            self.config_dir.mkdir(exist_ok=True)
            self.cache_dir.mkdir(exist_ok=True)
        except Exception as e:
            logging.warning(f"Could not create directory: {e}")
    
    def _validate_configuration(self):
        """
        Validate configuration values
        
        Raises:
            ConfigurationError: If configuration is invalid
        """
        # Ensure mtr_rounds is a positive integer
        if not isinstance(self.mtr_rounds, int) or self.mtr_rounds <= 0:
            raise ConfigurationError("mtr_rounds must be a positive integer")
        
        # Ensure max_concurrent_shodan_requests is a positive integer
        if not isinstance(self.max_concurrent_shodan_requests, int) or self.max_concurrent_shodan_requests <= 0:
            raise ConfigurationError("max_concurrent_shodan_requests must be a positive integer")
        
        # Ensure shodan_show_top_n is a positive integer
        if not isinstance(self.shodan_show_top_n, int) or self.shodan_show_top_n <= 0:
            raise ConfigurationError("shodan_show_top_n must be a positive integer")
    
    def _update_from_dict(self, config_data: Dict[str, Any]):
        """
        Update configuration from dictionary
        
        Args:
            config_data: Dictionary containing configuration values
        """
        # Update simple attributes
        for key, value in config_data.items():
            if hasattr(self, key) and not key.startswith('_'):
                setattr(self, key, value)
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert configuration to dictionary
        
        Returns:
            Dictionary representation of configuration
        """
        result = {}
        for key, value in self.__dict__.items():
            if not key.startswith('_'):
                result[key] = value
        return result
    
    def save(self, config_file: Optional[Path] = None):
        """
        Save configuration to file
        
        Args:
            config_file: Path to save configuration to (default: ~/.pyasn/config.yaml)
            
        Raises:
            ConfigurationError: If the file cannot be written
        """
        if config_file is None:
            config_file = self.config_dir / "config.yaml"
        
        try:
            # Create parent directory if it doesn't exist'
            config_file.parent.mkdir(exist_ok=True, parents=True)
            
            # Save configuration
            with open(config_file, 'w') as f:
                yaml.dump(self.to_dict(), f, default_flow_style=False)
        
        except Exception as e:
            raise ConfigurationError(f"Error saving configuration: {e}")