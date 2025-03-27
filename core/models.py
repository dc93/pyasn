"""
Data models for PyASN
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any

@dataclass
class ASNInfo:
    """ASN information model"""
    asn: str
    asname: str = ""
    org: str = ""
    holder: str = ""
    abuse_contacts: List[str] = field(default_factory=list)
    registration_date: Optional[str] = None
    asrank: str = "N/A"
    asrank_info: Dict[str, Any] = field(default_factory=dict)
    prefix_count_v4: int = 0
    prefix_count_v6: int = 0
    bgp_peer_count: int = 0
    announced_prefixes: Dict[str, List[str]] = field(default_factory=lambda: {"v4": [], "v6": []})
    ixp_presence: List[str] = field(default_factory=list)
    bgp_peers: Dict[str, List[str]] = field(default_factory=lambda: {
        "upstream": [],
        "downstream": [],
        "uncertain": []
    })
    bgp_hijack_incidents: Dict[str, int] = field(default_factory=lambda: {
        "total": 0,
        "as_hijacker": 0,
        "as_victim": 0
    })
    bgp_leak_incidents: Dict[str, int] = field(default_factory=lambda: {
        "total": 0
    })

@dataclass
class IPInfo:
    """IP address information model"""
    ip: str
    ip_version: str
    org_name: str = ""
    net_range: str = ""
    net_name: str = ""
    abuse_contacts: List[str] = field(default_factory=list)
    reverse: Optional[str] = None
    routing: Dict[str, Any] = field(default_factory=dict)
    type: Dict[str, Any] = field(default_factory=dict)
    geolocation: Dict[str, Any] = field(default_factory=dict)
    reputation: Dict[str, Any] = field(default_factory=dict)
    fingerprinting: Dict[str, Any] = field(default_factory=dict)

@dataclass
class TraceHop:
    """Single hop in a traceroute"""
    hop: int
    ip: Optional[str] = None
    ping: Optional[float] = None
    loss: float = 0
    hostname: str = ""
    asn: str = ""
    as_name: str = ""
    geolocation: Dict[str, Any] = field(default_factory=dict)
    rpki: Dict[str, Any] = field(default_factory=dict)

@dataclass
class ASHop:
    """AS hop in an AS path"""
    asn: str
    as_name: str
    is_source: bool = False
    is_destination: bool = False

@dataclass
class TracePath:
    """Trace path results"""
    target: str
    completed: bool = False
    runtime: float = 0
    resolved_ip: Optional[str] = None
    source: Dict[str, Any] = field(default_factory=dict)
    hops: List[TraceHop] = field(default_factory=list)
    as_path: List[ASHop] = field(default_factory=list)
    error: Optional[str] = None

@dataclass
class OrganizationSearchResult:
    """Organization search results"""
    query: str
    matches: List[str] = field(default_factory=list)
    ipv4_networks: List[Dict[str, Any]] = field(default_factory=list)
    ipv6_networks: List[Dict[str, Any]] = field(default_factory=list)

@dataclass
class ShodanHost:
    """Shodan host information"""
    ip: str
    ports: List[int] = field(default_factory=list)
    cpes: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    vulns: List[str] = field(default_factory=list)
    hostnames: List[str] = field(default_factory=list)

@dataclass
class ShodanScanResult:
    """Shodan scan results"""
    summary: Dict[str, Any] = field(default_factory=dict)
    host_data: List[ShodanHost] = field(default_factory=list)

@dataclass
class GeolocateResult:
    """Bulk geolocation results"""
    total_ips: int
    unique_ips: int
    ip_counts: Dict[str, int] = field(default_factory=dict)
    country_stats: Dict[str, int] = field(default_factory=dict)
    geolocation_data: List[Dict[str, Any]] = field(default_factory=list)

@dataclass
class CountryCIDRResult:
    """Country CIDR lookup results"""
    country_name: str = ""
    country_code: str = ""
    population: int = 0
    ipv4_blocks: List[str] = field(default_factory=list)
    ipv4_total_ips: int = 0
    ipv4_per_capita: float = 0
    ipv6_blocks: List[str] = field(default_factory=list)