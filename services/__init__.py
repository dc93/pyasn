"""
PyASN service interfaces
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any

from pyasn.core.models import (
    ASNInfo, IPInfo, TracePath, OrganizationSearchResult,
    ShodanScanResult, GeolocateResult, CountryCIDRResult
)

class ASNService(ABC):
    """Interface for ASN lookup services"""
    
    @abstractmethod
    def lookup_asn(self, asn: str) -> ASNInfo:
        """
        Look up information for an AS number
        
        Args:
            asn: The AS number (with or without 'AS' prefix)
            
        Returns:
            ASNInfo object with ASN information
            
        Raises:
            ValidationError: If ASN is invalid
            LookupError: If lookup fails
        """
        pass
    
    @abstractmethod
    def suggest_asns(self, search_term: str) -> List[Dict[str, str]]:
        """
        Search for ASNs matching a given term
        
        Args:
            search_term: The search term to look for
            
        Returns:
            List of matching ASNs with information
            
        Raises:
            LookupError: If lookup fails
        """
        pass

class IPService(ABC):
    """Interface for IP lookup services"""
    
    @abstractmethod
    def lookup_ip(self, ip: str) -> IPInfo:
        """
        Look up information for an IP address
        
        Args:
            ip: The IP address to look up
            
        Returns:
            IPInfo object with IP information
            
        Raises:
            ValidationError: If IP is invalid
            LookupError: If lookup fails
        """
        pass
    
    @abstractmethod
    def bulk_geolocate(self, ips: List[str]) -> GeolocateResult:
        """
        Bulk geolocate a list of IP addresses
        
        Args:
            ips: List of IP addresses to geolocate
            
        Returns:
            GeolocateResult object with geolocation results
            
        Raises:
            ValidationError: If any IP is invalid
            LookupError: If lookup fails
        """
        pass
    
    @abstractmethod
    def country_cidr_lookup(self, country: str) -> CountryCIDRResult:
        """
        Look up all CIDR blocks allocated to a country
        
        Args:
            country: Country name or code
            
        Returns:
            CountryCIDRResult object with country information and CIDR blocks
            
        Raises:
            LookupError: If lookup fails
        """
        pass

class TraceService(ABC):
    """Interface for path tracing services"""
    
    @abstractmethod
    def trace_as_path(self, target: str) -> TracePath:
        """
        Trace the AS path to a target
        
        Args:
            target: Target IP or hostname
            
        Returns:
            TracePath object with trace results
            
        Raises:
            ValidationError: If target is invalid
            NetworkError: If tracing fails
        """
        pass

class OrganizationService(ABC):
    """Interface for organization search services"""
    
    @abstractmethod
    def search_by_org(self, org_name: str) -> OrganizationSearchResult:
        """
        Search for network ranges related to an organization
        
        Args:
            org_name: Organization name to search for
            
        Returns:
            OrganizationSearchResult object with organization information and network ranges
            
        Raises:
            ValidationError: If org_name is invalid
            LookupError: If search fails
        """
        pass

class ShodanService(ABC):
    """Interface for Shodan scanning services"""
    
    @abstractmethod
    def scan(self, targets: List[str]) -> ShodanScanResult:
        """
        Scan targets using Shodan InternetDB
        
        Args:
            targets: List of targets (IPs, hostnames, CIDRs, URLs)
            
        Returns:
            ShodanScanResult object with scan results
            
        Raises:
            ValidationError: If any target is invalid
            LookupError: If scan fails
        """
        pass