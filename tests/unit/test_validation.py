"""
Unit tests for Validator class
"""

import unittest

from pyasn.core.exceptions import ValidationError
from pyasn.utils.validation import Validator

class TestValidator(unittest.TestCase):
    """Test Validator class"""
    
    def test_validate_required(self):
        """Test validate_required method"""
        # Valid values should not raise exceptions
        Validator.validate_required("value", "test_value")
        Validator.validate_required(123, "test_value")
        Validator.validate_required([1, 2, 3], "test_value")
        Validator.validate_required({"key": "value"}, "test_value")
        
        # None should raise exception
        with self.assertRaises(ValidationError):
            Validator.validate_required(None, "test_value")
        
        # Empty string should raise exception
        with self.assertRaises(ValidationError):
            Validator.validate_required("", "test_value")
        
        # Empty list should raise exception
        with self.assertRaises(ValidationError):
            Validator.validate_required([], "test_value")
        
        # Empty dict should raise exception
        with self.assertRaises(ValidationError):
            Validator.validate_required({}, "test_value")
    
    def test_validate_ip(self):
        """Test validate_ip method"""
        # Valid IPs should not raise exceptions
        Validator.validate_ip("192.168.1.1")
        Validator.validate_ip("2001:db8::1")
        
        # Invalid IPs should raise exceptions
        with self.assertRaises(ValidationError):
            Validator.validate_ip("256.0.0.1")
        
        with self.assertRaises(ValidationError):
            Validator.validate_ip("2001:db8::gggg")
        
        with self.assertRaises(ValidationError):
            Validator.validate_ip("example.com")
    
    def test_validate_asn(self):
        """Test validate_asn method"""
        # Valid ASNs should not raise exceptions
        Validator.validate_asn("15169")
        Validator.validate_asn("AS15169")
        
        # Invalid ASNs should raise exceptions
        with self.assertRaises(ValidationError):
            Validator.validate_asn("0")
        
        with self.assertRaises(ValidationError):
            Validator.validate_asn("AS")
        
        with self.assertRaises(ValidationError):
            Validator.validate_asn("example.com")
    
    def test_validate_cidr(self):
        """Test validate_cidr method"""
        # Valid CIDRs should not raise exceptions
        Validator.validate_cidr("192.168.1.0/24")
        Validator.validate_cidr("2001:db8::/32")
        
        # Invalid CIDRs should raise exceptions
        with self.assertRaises(ValidationError):
            Validator.validate_cidr("192.168.1.1")
        
        with self.assertRaises(ValidationError):
            Validator.validate_cidr("192.168.1.0/33")
    
    def test_validate_hostname(self):
        """Test validate_hostname method"""
        # Valid hostnames should not raise exceptions
        Validator.validate_hostname("example.com")
        Validator.validate_hostname("sub.example.com")
        
        # Invalid hostnames should raise exceptions
        with self.assertRaises(ValidationError):
            Validator.validate_hostname("example..com")
        
        with self.assertRaises(ValidationError):
            Validator.validate_hostname("example.com/path")
    
    def test_validate_url(self):
        """Test validate_url method"""
        # Valid URLs should not raise exceptions
        Validator.validate_url("http://example.com")
        Validator.validate_url("https://example.com/path")
        
        # Invalid URLs should raise exceptions
        with self.assertRaises(ValidationError):
            Validator.validate_url("example.com")
        
        with self.assertRaises(ValidationError):
            Validator.validate_url("http://")
    
    def test_validate_port(self):
        """Test validate_port method"""
        # Valid ports should not raise exceptions
        Validator.validate_port(80)
        Validator.validate_port("443")
        Validator.validate_port(65535)
        
        # Invalid ports should raise exceptions
        with self.assertRaises(ValidationError):
            Validator.validate_port(0)
        
        with self.assertRaises(ValidationError):
            Validator.validate_port(65536)
        
        with self.assertRaises(ValidationError):
            Validator.validate_port("abc")
    
    def test_validate_integer_range(self):
        """Test validate_integer_range method"""
        # Valid integers should not raise exceptions
        Validator.validate_integer_range(5, "test_value", 1, 10)
        Validator.validate_integer_range("5", "test_value", 1, 10)
        Validator.validate_integer_range(1, "test_value", 1, 10)
        Validator.validate_integer_range(10, "test_value", 1, 10)
        
        # Invalid integers should raise exceptions
        with self.assertRaises(ValidationError):
            Validator.validate_integer_range(0, "test_value", 1, 10)
        
        with self.assertRaises(ValidationError):
            Validator.validate_integer_range(11, "test_value", 1, 10)
        
        with self.assertRaises(ValidationError):
            Validator.validate_integer_range("abc", "test_value", 1, 10)
    
    def test_validate_choice(self):
        """Test validate_choice method"""
        # Valid choices should not raise exceptions
        Validator.validate_choice("a", ["a", "b", "c"], "test_value")
        Validator.validate_choice(1, [1, 2, 3], "test_value")
        
        # Invalid choices should raise exceptions
        with self.assertRaises(ValidationError):
            Validator.validate_choice("d", ["a", "b", "c"], "test_value")
        
        with self.assertRaises(ValidationError):
            Validator.validate_choice(4, [1, 2, 3], "test_value")

if __name__ == "__main__":
    unittest.main()