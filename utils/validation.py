"""
Input validation utilities for PyASN
"""

import re
from typing import Any, Dict, List, Optional, Union

from pyasn.core.exceptions import ValidationError
from pyasn.utils.network import NetworkUtils

class Validator:
    """Input validation utilities"""
    
    @staticmethod
    def validate_required(value: Any, name: str) -> None:
        """
        Validate that a value is not None or empty
        
        Args:
            value: Value to validate
            name: Name of the value for error messages
            
        Raises:
            ValidationError: If value is None or empty
        """
        if value is None:
            raise ValidationError(f"{name} is required")
        
        if isinstance(value, (str, list, dict)) and not value:
            raise ValidationError(f"{name} cannot be empty")
    
    @staticmethod
    def validate_ip(ip: str) -> None:
        """
        Validate an IP address
        
        Args:
            ip: IP address to validate
            
        Raises:
            ValidationError: If IP is invalid
        """
        if not NetworkUtils.is_valid_ip(ip):
            raise ValidationError(f"Invalid IP address: {ip}")
    
    @staticmethod
    def validate_asn(asn: str) -> None:
        """
        Validate an ASN
        
        Args:
            asn: ASN to validate
            
        Raises:
            ValidationError: If ASN is invalid
        """
        if not NetworkUtils.is_asn(asn):
            raise ValidationError(f"Invalid ASN: {asn}")
    
    @staticmethod
    def validate_cidr(cidr: str) -> None:
        """
        Validate CIDR notation
        
        Args:
            cidr: CIDR to validate
            
        Raises:
            ValidationError: If CIDR is invalid
        """
        if not NetworkUtils.is_valid_cidr(cidr):
            raise ValidationError(f"Invalid CIDR notation: {cidr}")
    
    @staticmethod
    def validate_hostname(hostname: str) -> None:
        """
        Validate a hostname
        
        Args:
            hostname: Hostname to validate
            
        Raises:
            ValidationError: If hostname is invalid
        """
        # Simple hostname validation
        hostname_pattern = r'^([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])(\.([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9]))*$'
        if not re.match(hostname_pattern, hostname):
            raise ValidationError(f"Invalid hostname: {hostname}")
    
    @staticmethod
    def validate_url(url: str) -> None:
        """
        Validate a URL
        
        Args:
            url: URL to validate
            
        Raises:
            ValidationError: If URL is invalid
        """
        if not NetworkUtils.is_url(url):
            raise ValidationError(f"Invalid URL: {url}")
    
    @staticmethod
    def validate_port(port: Union[str, int]) -> None:
        """
        Validate a port number
        
        Args:
            port: Port number to validate
            
        Raises:
            ValidationError: If port is invalid
        """
        try:
            port_num = int(port)
            if port_num < 1 or port_num > 65535:
                raise ValidationError(f"Port number must be between 1 and 65535: {port}")
        except ValueError:
            raise ValidationError(f"Invalid port number: {port}")

    @staticmethod
    def validate_integer_range(value: Union[str, int], name: str, min_value: int, max_value: int) -> None:
        """
        Validate an integer within a range
        
        Args:
            value: Value to validate
            name: Name of the value for error messages
            min_value: Minimum allowed value
            max_value: Maximum allowed value
            
        Raises:
            ValidationError: If value is not an integer or outside the range
        """
        try:
            int_value = int(value)
            if int_value < min_value or int_value > max_value:
                raise ValidationError(f"{name} must be between {min_value} and {max_value}: {value}")
        except ValueError:
            raise ValidationError(f"{name} must be an integer: {value}")
    
    @staticmethod
    def validate_choice(value: Any, choices: List[Any], name: str) -> None:
        """
        Validate that a value is one of the allowed choices
        
        Args:
            value: Value to validate
            choices: List of allowed choices
            name: Name of the value for error messages
            
        Raises:
            ValidationError: If value is not in choices
        """
        if value not in choices:
            raise ValidationError(f"{name} must be one of: {', '.join(str(c) for c in choices)}")