"""
Unit tests for NetworkUtils
"""

import unittest
from unittest.mock import patch, MagicMock

from pyasn.utils.network import NetworkUtils

class TestNetworkUtils(unittest.TestCase):
    """Test NetworkUtils class"""
    
    def test_is_ipv4(self):
        """Test is_ipv4 method"""
        self.assertTrue(NetworkUtils.is_ipv4("192.168.1.1"))
        self.assertTrue(NetworkUtils.is_ipv4("8.8.8.8"))
        self.assertTrue(NetworkUtils.is_ipv4("255.255.255.255"))
        self.assertTrue(NetworkUtils.is_ipv4("0.0.0.0"))
        
        self.assertFalse(NetworkUtils.is_ipv4("256.0.0.1"))
        self.assertFalse(NetworkUtils.is_ipv4("192.168.1"))
        self.assertFalse(NetworkUtils.is_ipv4("192.168.1.1.1"))
        self.assertFalse(NetworkUtils.is_ipv4("2001:db8::1"))
        self.assertFalse(NetworkUtils.is_ipv4("example.com"))
    
    def test_is_ipv6(self):
        """Test is_ipv6 method"""
        self.assertTrue(NetworkUtils.is_ipv6("2001:db8::1"))
        self.assertTrue(NetworkUtils.is_ipv6("::1"))
        self.assertTrue(NetworkUtils.is_ipv6("fe80::1234:5678:abcd:ef12"))
        
        self.assertFalse(NetworkUtils.is_ipv6("192.168.1.1"))
        self.assertFalse(NetworkUtils.is_ipv6("2001:db8::gggg"))
        self.assertFalse(NetworkUtils.is_ipv6("example.com"))
    
    def test_is_valid_ip(self):
        """Test is_valid_ip method"""
        self.assertTrue(NetworkUtils.is_valid_ip("192.168.1.1"))
        self.assertTrue(NetworkUtils.is_valid_ip("2001:db8::1"))
        
        self.assertFalse(NetworkUtils.is_valid_ip("256.0.0.1"))
        self.assertFalse(NetworkUtils.is_valid_ip("2001:db8::gggg"))
        self.assertFalse(NetworkUtils.is_valid_ip("example.com"))
    
    def test_is_valid_cidr(self):
        """Test is_valid_cidr method"""
        self.assertTrue(NetworkUtils.is_valid_cidr("192.168.1.0/24"))
        self.assertTrue(NetworkUtils.is_valid_cidr("10.0.0.0/8"))
        self.assertTrue(NetworkUtils.is_valid_cidr("2001:db8::/32"))
        
        self.assertFalse(NetworkUtils.is_valid_cidr("192.168.1.1"))
        self.assertFalse(NetworkUtils.is_valid_cidr("192.168.1.0/33"))
        self.assertFalse(NetworkUtils.is_valid_cidr("example.com/24"))
    
    def test_is_asn(self):
        """Test is_asn method"""
        self.assertTrue(NetworkUtils.is_asn("15169"))
        self.assertTrue(NetworkUtils.is_asn("AS15169"))
        self.assertTrue(NetworkUtils.is_asn("as15169"))
        
        self.assertFalse(NetworkUtils.is_asn("0"))
        self.assertFalse(NetworkUtils.is_asn("4294967296"))  # Max ASN + 1
        self.assertFalse(NetworkUtils.is_asn("AS"))
        self.assertFalse(NetworkUtils.is_asn("example.com"))
    
    def test_normalize_asn(self):
        """Test normalize_asn method"""
        self.assertEqual(NetworkUtils.normalize_asn("15169"), "15169")
        self.assertEqual(NetworkUtils.normalize_asn("AS15169"), "15169")
        self.assertEqual(NetworkUtils.normalize_asn("as15169"), "15169")
    
    def test_is_hostname(self):
        """Test is_hostname method"""
        self.assertTrue(NetworkUtils.is_hostname("example.com"))
        self.assertTrue(NetworkUtils.is_hostname("sub.example.com"))
        self.assertTrue(NetworkUtils.is_hostname("example.co.uk"))
        
        self.assertFalse(NetworkUtils.is_hostname("192.168.1.1"))
        self.assertFalse(NetworkUtils.is_hostname("2001:db8::1"))
        self.assertFalse(NetworkUtils.is_hostname("example com"))
        self.assertFalse(NetworkUtils.is_hostname("example"))
    
    def test_is_url(self):
        """Test is_url method"""
        self.assertTrue(NetworkUtils.is_url("http://example.com"))
        self.assertTrue(NetworkUtils.is_url("https://example.com"))
        self.assertTrue(NetworkUtils.is_url("http://example.com/path?query=value"))
        
        self.assertFalse(NetworkUtils.is_url("example.com"))
        self.assertFalse(NetworkUtils.is_url("192.168.1.1"))
    
    def test_extract_hostname_from_url(self):
        """Test extract_hostname_from_url method"""
        self.assertEqual(NetworkUtils.extract_hostname_from_url("http://example.com"), "example.com")
        self.assertEqual(NetworkUtils.extract_hostname_from_url("https://sub.example.com/path"), "sub.example.com")
        self.assertEqual(NetworkUtils.extract_hostname_from_url("http://example.com:8080/path"), "example.com")
    
    def test_extract_ips_from_text(self):
        """Test extract_ips_from_text method"""
        text = """
        IPv4 addresses:
        192.168.1.1
        10.0.0.1
        8.8.8.8
        
        IPv6 addresses:
        2001:db8::1
        fe80::1
        """
        
        ips = NetworkUtils.extract_ips_from_text(text)
        self.assertIn("192.168.1.1", ips)
        self.assertIn("10.0.0.1", ips)
        self.assertIn("8.8.8.8", ips)
        self.assertIn("2001:db8::1", ips)
        self.assertIn("fe80::1", ips)
    
    @patch('dns.resolver.resolve')
    def test_resolve_hostname(self, mock_resolve):
        """Test resolve_hostname method"""
        # Mock DNS lookup for IPv4
        mock_a_answer = MagicMock()
        mock_a_answer.address = "93.184.216.34"
        mock_resolve.side_effect = [
            [mock_a_answer],  # A record
            []  # AAAA record (empty)
        ]
        
        # Test hostname resolution
        ips = NetworkUtils.resolve_hostname("example.com")
        self.assertEqual(ips, ["93.184.216.34"])
        
        # Verify the correct calls were made
        mock_resolve.assert_any_call("example.com", "A")
        mock_resolve.assert_any_call("example.com", "AAAA")

if __name__ == "__main__":
    unittest.main()