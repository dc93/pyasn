"""
Network utility functions for PyASN
"""

import ipaddress
import logging
import platform
import re
import socket
import subprocess
from typing import List, Optional, Dict, Tuple
from urllib.parse import urlparse

import dns.resolver
import dns.reversename
import requests

from pyasn.core.exceptions import NetworkError, ValidationError

# Regular expressions for IP address matching
IPV4_REGEX = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
IPV6_REGEX = r'([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])'
IPV4V6_REGEX = f'({IPV4_REGEX}|{IPV6_REGEX})'

class NetworkUtils:
    """Networking utility functions"""
    
    @staticmethod
    def is_ipv4(ip: str) -> bool:
        """
        Check if the string is a valid IPv4 address
        
        Args:
            ip: String to check
            
        Returns:
            True if valid IPv4 address, False otherwise
        """
        try:
            ipaddress.IPv4Address(ip)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def is_ipv6(ip: str) -> bool:
        """
        Check if the string is a valid IPv6 address
        
        Args:
            ip: String to check
            
        Returns:
            True if valid IPv6 address, False otherwise
        """
        try:
            ipaddress.IPv6Address(ip)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def is_valid_ip(ip: str) -> bool:
        """
        Check if the string is a valid IP address (v4 or v6)
        
        Args:
            ip: String to check
            
        Returns:
            True if valid IP address, False otherwise
        """
        return NetworkUtils.is_ipv4(ip) or NetworkUtils.is_ipv6(ip)
    
    @staticmethod
    def is_valid_cidr(cidr: str) -> bool:
        """
        Check if the string is a valid CIDR notation
        
        Args:
            cidr: String to check
            
        Returns:
            True if valid CIDR notation, False otherwise
        """
        try:
            ipaddress.ip_network(cidr, strict=False)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def is_asn(input_str: str) -> bool:
        """
        Check if the string is a valid ASN format
        
        Args:
            input_str: String to check
            
        Returns:
            True if valid ASN format, False otherwise
        """
        # ASN can be 'AS123' or just '123'
        pattern = r'^(?:[aA][sS])?(\d+)$'
        match = re.match(pattern, input_str)
        if match:
            asn_num = int(match.group(1))
            return 1 <= asn_num <= 4294967295  # Valid ASN range
        return False
    
    @staticmethod
    def normalize_asn(asn: str) -> str:
        """
        Normalize ASN format (strip 'AS' prefix if present and return number)
        
        Args:
            asn: ASN to normalize
            
        Returns:
            Normalized ASN (without 'AS' prefix)
        """
        return re.sub(r'^[aA][sS]', '', asn)
    
    @staticmethod
    def is_hostname(input_str: str) -> bool:
        """
        Check if the string is likely a hostname
        
        Args:
            input_str: String to check
            
        Returns:
            True if likely a hostname, False otherwise
        """
        # Simple check: contains at least one dot and no spaces
        return '.' in input_str and ' ' not in input_str and not NetworkUtils.is_valid_ip(input_str)
    
    @staticmethod
    def is_url(input_str: str) -> bool:
        """
        Check if the string is a URL
        
        Args:
            input_str: String to check
            
        Returns:
            True if a URL, False otherwise
        """
        try:
            result = urlparse(input_str)
            return all([result.scheme, result.netloc])
        except ValueError:
            return False
    
    @staticmethod
    def extract_hostname_from_url(url: str) -> str:
        """
        Extract hostname from URL
        
        Args:
            url: URL to extract hostname from
            
        Returns:
            Hostname portion of the URL
        """
        parsed = urlparse(url)
        return parsed.netloc.split(':')[0]  # Remove port if present
    
    @staticmethod
    def extract_ips_from_text(text: str) -> List[str]:
        """
        Extract all IP addresses from text
        
        Args:
            text: Text to extract IPs from
            
        Returns:
            List of IP addresses found in the text
        """
        ipv4_matches = re.findall(IPV4_REGEX, text)
        ipv6_matches = re.findall(IPV6_REGEX, text)
        return ipv4_matches + ipv6_matches
    
    @staticmethod
    def resolve_hostname(hostname: str) -> List[str]:
        """
        Resolve hostname to IP addresses
        
        Args:
            hostname: Hostname to resolve
            
        Returns:
            List of IP addresses for the hostname
            
        Raises:
            NetworkError: If hostname cannot be resolved
        """
        try:
            # Get IPv4 addresses
            ipv4_addresses = []
            try:
                answers = dns.resolver.resolve(hostname, 'A')
                ipv4_addresses = [answer.address for answer in answers]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass
            
            # Get IPv6 addresses
            ipv6_addresses = []
            try:
                answers = dns.resolver.resolve(hostname, 'AAAA')
                ipv6_addresses = [answer.address for answer in answers]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass
            
            if not ipv4_addresses and not ipv6_addresses:
                raise NetworkError(f"Could not resolve hostname: {hostname}")
            
            return ipv4_addresses + ipv6_addresses
            
        except dns.exception.DNSException as e:
            raise NetworkError(f"DNS resolution failed for {hostname}: {e}")
        except Exception as e:
            logging.error(f"Error resolving hostname {hostname}: {e}")
            raise NetworkError(f"Failed to resolve hostname {hostname}: {e}")
    
    @staticmethod
    def get_ptr_record(ip: str) -> Optional[str]:
        """
        Get PTR record (reverse DNS) for an IP address
        
        Args:
            ip: IP address to get PTR record for
            
        Returns:
            PTR record for the IP address, or None if not found
        """
        try:
            if NetworkUtils.is_ipv4(ip):
                addr = dns.reversename.from_address(ip)
            else:
                addr = dns.reversename.from_address(ip)
            
            answers = dns.resolver.resolve(addr, 'PTR')
            return str(answers[0]).rstrip('.')
        except Exception as e:
            logging.debug(f"Could not get PTR record for {ip}: {e}")
            return None
    
    @staticmethod
    def traceroute(target: str, count: int = 5) -> List[Dict]:
        """
        Perform a traceroute to the target
        
        Args:
            target: The target IP or hostname
            count: Number of packets to send at each hop
            
        Returns:
            List of hops with information
            
        Raises:
            NetworkError: If traceroute fails
        """
        result = []
        try:
            # Determine the appropriate traceroute command based on platform
            if platform.system() == "Windows":
                # Windows uses tracert which doesn't have a count parameter'
                cmd = ["tracert", "-d", target]
                pattern = r'^\s*(\d+)\s+(\d+)\s+ms\s+(\d+)\s+ms\s+(\d+)\s+ms\s+(\S+)'
            elif platform.system() == "Darwin":  # macOS
                cmd = ["traceroute", "-n", "-q", str(count), target]
                pattern = r'^\s*(\d+)\s+(\S+)'
            else:  # Linux and others
                cmd = ["traceroute", "-n", "-q", str(count), target]
                pattern = r'^\s*(\d+)\s+(\S+)'

            # Run the traceroute command
            process = subprocess.Popen(
                cmd, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Process output line by line
            for line in process.stdout:
                if platform.system() == "Windows":
                    match = re.search(pattern, line)
                    if match:
                        hop_num = int(match.group(1))
                        ip = match.group(5)
                        # Average the three ping times
                        ping_times = [float(match.group(i)) for i in range(2, 5)]
                        avg_ping = sum(ping_times) / len(ping_times)
                        
                        result.append({
                            "hop": hop_num,
                            "ip": ip,
                            "ping": avg_ping
                        })
                else:
                    match = re.search(pattern, line)
                    if match:
                        hop_num = int(match.group(1))
                        ip = match.group(2)
                        
                        # Extract ping times (different format on Unix systems)
                        ping_pattern = r'(\d+.\d+)\s+ms'
                        ping_times = re.findall(ping_pattern, line)
                        avg_ping = sum(float(p) for p in ping_times) / len(ping_times) if ping_times else 0
                        
                        result.append({
                            "hop": hop_num,
                            "ip": ip,
                            "ping": avg_ping
                        })
            
            process.wait()
            
            # Handle errors
            if process.returncode != 0:
                error = process.stderr.read()
                raise NetworkError(f"Traceroute failed: {error}")
                
            return result
        
        except NetworkError:
            raise
        except Exception as e:
            raise NetworkError(f"Error performing traceroute: {e}")

    @staticmethod
    def what_is_my_ip(force_ipv4=False) -> Optional[str]:
        """
        Get public IP address
        
        Args:
            force_ipv4: Force IPv4 address
            
        Returns:
            Public IP address, or None if it cannot be determined
        """
        try:
            if force_ipv4:
                response = requests.get("https://api.ipify.org", timeout=5)
                return response.text.strip()
            else:
                # Try IPv6 first
                try:
                    response = requests.get("https://api6.ipify.org", timeout=5)
                    return response.text.strip()
                except:
                    # Fall back to IPv4
                    response = requests.get("https://api.ipify.org", timeout=5)
                    return response.text.strip()
        except Exception as e:
            logging.error(f"Error getting public IP: {e}")
            return None

    @staticmethod
    def cidr_to_ip_list(cidr: str) -> List[str]:
        """
        Convert CIDR to list of IP addresses (limited to /24 or smaller for safety)
        
        Args:
            cidr: CIDR notation
            
        Returns:
            List of IP addresses in the CIDR block
            
        Raises:
            ValidationError: If CIDR is invalid
        """
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            # For safety, limit to /24 or smaller for IPv4 and /120 or smaller for IPv6
            if (network.version == 4 and network.prefixlen < 24) or \
               (network.version == 6 and network.prefixlen < 120):
                return [str(network.network_address)]  # Just return the network address
            return [str(ip) for ip in network.hosts()]
        except ValueError as e:
            raise ValidationError(f"Invalid CIDR notation: {e}")
        except Exception as e:
            logging.error(f"Error converting CIDR to IP list: {e}")
            raise NetworkError(f"Failed to process CIDR: {e}")