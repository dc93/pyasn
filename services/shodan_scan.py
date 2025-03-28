"""
Shodan scanning implementation
"""

import logging
import concurrent.futures
from typing import Dict, List, Optional, Any
from collections import Counter

import requests

from pyasn.core.config import Config
from pyasn.core.exceptions import (
    ValidationError, NetworkError, APIError, DataParsingError,
    LookupError
)
from pyasn.core.models import ShodanScanResult, ShodanHost
from pyasn.services import ShodanService
from pyasn.utils.cache import Cache
from pyasn.utils.network import NetworkUtils
from pyasn.utils.validation import Validator

class ShodanScanService(ShodanService):
    """Shodan scanning service implementation"""
    
    def __init__(self, config: Config, network_utils=None, cache=None):
        """
        Initialize Shodan scanning service
        
        Args:
            config: Configuration object
            network_utils: NetworkUtils instance (optional)
            cache: Cache instance (optional)
        """
        self.config = config
        self.network_utils = network_utils or NetworkUtils()
        self.cache = cache or Cache(config.cache_dir)
    
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
        Validator.validate_required(targets, "targets")
        
        try:
            result = ShodanScanResult(
                summary={
                    "total_targets": len(targets),
                    "scanned_ips": 0,
                    "hosts_with_data": 0,
                    "top_ports": {},
                    "top_cpes": {},
                    "top_tags": {},
                    "vulnerabilities": []
                },
                host_data=[]
            )
            
            # Expand targets to IPs
            ips_to_scan = []
            for target in targets:
                # Check if target is a CIDR
                if "/" in target and self.network_utils.is_valid_cidr(target):
                    ips_to_scan.extend(self.network_utils.cidr_to_ip_list(target))
                # Check if target is a URL
                elif self.network_utils.is_url(target):
                    hostname = self.network_utils.extract_hostname_from_url(target)
                    resolved_ips = self.network_utils.resolve_hostname(hostname)
                    ips_to_scan.extend(resolved_ips)
                # Check if target is a hostname
                elif self.network_utils.is_hostname(target):
                    resolved_ips = self.network_utils.resolve_hostname(target)
                    ips_to_scan.extend(resolved_ips)
                # If it's an IP, add it directly'
                elif self.network_utils.is_valid_ip(target):
                    ips_to_scan.append(target)
            
            # Filter out IPv6 addresses (Shodan InternetDB doesn't support them yet)'
            ips_to_scan = [ip for ip in ips_to_scan if self.network_utils.is_ipv4(ip)]
            result.summary["scanned_ips"] = len(ips_to_scan)
            
            # If no valid IPs to scan, return early
            if not ips_to_scan:
                return result
            
            # Scan IPs in batches
            batch_size = min(len(ips_to_scan), self.config.max_concurrent_shodan_requests)
            ip_batches = [ips_to_scan[i:i + batch_size] for i in range(0, len(ips_to_scan), batch_size)]
            
            all_ports = Counter()
            all_cpes = Counter()
            all_tags = Counter()
            all_vulns = []
            
            for batch in ip_batches:
                with concurrent.futures.ThreadPoolExecutor(max_workers=batch_size) as executor:
                    future_to_ip = {executor.submit(self._scan_single_ip, ip): ip for ip in batch}
                    
                    for future in concurrent.futures.as_completed(future_to_ip):
                        ip = future_to_ip[future]
                        try:
                            data = future.result()
                            if data:
                                # Convert to ShodanHost model
                                host = ShodanHost(
                                    ip=data["ip"],
                                    ports=data.get("ports", []),
                                    cpes=data.get("cpes", []),
                                    tags=data.get("tags", []),
                                    vulns=data.get("vulns", []),
                                    hostnames=data.get("hostnames", [])
                                )
                                
                                result.host_data.append(host)
                                
                                # Update statistics
                                all_ports.update(host.ports)
                                all_cpes.update(host.cpes)
                                all_tags.update(host.tags)
                                all_vulns.extend(host.vulns)
                        except Exception as e:
                            logging.warning(f"Error processing scan result for IP {ip}: {e}")
            
            # Update summary
            result.summary["hosts_with_data"] = len(result.host_data)
            result.summary["top_ports"] = dict(all_ports.most_common(self.config.shodan_show_top_n))
            result.summary["top_cpes"] = dict(all_cpes.most_common(self.config.shodan_show_top_n))
            result.summary["top_tags"] = dict(all_tags.most_common(self.config.shodan_show_top_n))
            
            # Get vulnerability details
            top_vulns = Counter(all_vulns).most_common(self.config.shodan_show_top_n)
            vuln_details = []
            
            for vuln, count in top_vulns:
                vuln_detail = {
                    "cve_id": vuln,
                    "count": count,
                    "details": self._get_vuln_details(vuln)
                }
                vuln_details.append(vuln_detail)
            
            result.summary["vulnerabilities"] = vuln_details
            
            return result
        
        except (ValidationError, NetworkError, APIError) as e:
            raise
        except Exception as e:
            logging.error(f"Unexpected error in Shodan scan: {e}")
            raise LookupError(f"Shodan scan failed: {e}")
    
    def _scan_single_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        """
        Scan a single IP with Shodan InternetDB
        
        Args:
            ip: IP to scan
            
        Returns:
            Dictionary with scan results, or None if no data
            
        Raises:
            APIError: If Shodan API request fails
        """
        try:
            # Try to get from cache
            cache_key = f"shodan_scan_{ip}"
            cached_result = self.cache.get(cache_key)
            if cached_result:
                return cached_result
            
            url = f"https://internetdb.shodan.io/{ip}"
            response = requests.get(url, timeout=10)
            
            # Check if we got valid JSON data
            if response.status_code == 200 and "No information available" not in response.text:
                data = response.json()
                
                # Create structured result
                result = {
                    "ip": ip,
                    "ports": data.get("ports", []),
                    "cpes": data.get("cpes", []),
                    "tags": data.get("tags", []),
                    "vulns": list(data.get("vulns", {})),
                    "hostnames": data.get("hostnames", [])
                }
                
                # Cache the result
                self.cache.set(cache_key, result)
                
                return result
            
            return None
        
        except requests.exceptions.RequestException as e:
            logging.warning(f"Error scanning IP {ip} with Shodan: {e}")
            return None
        except Exception as e:
            logging.warning(f"Error processing Shodan data for IP {ip}: {e}")
            return None
    
    def _get_vuln_details(self, cve_id: str) -> Dict[str, str]:
        """
        Get details for a CVE from NIST NVD
        
        Args:
            cve_id: CVE ID to get details for
            
        Returns:
            Dictionary with vulnerability details
        """
        result = {
            "name": "",
            "description": "",
            "score": "",
            "severity": "",
            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        }
        
        try:
            # Try to get from cache
            cache_key = f"vuln_details_{cve_id}"
            cached_result = self.cache.get(cache_key)
            if cached_result:
                return cached_result
            
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            data = response.json()
            
            if data.get("vulnerabilities") and len(data["vulnerabilities"]) > 0:
                vuln = data["vulnerabilities"][0].get("cve", {})
                
                # Get name
                result["name"] = vuln.get("cisaVulnerabilityName", "")
                
                # Get description
                if vuln.get("descriptions") and len(vuln["descriptions"]) > 0:
                    for desc in vuln["descriptions"]:
                        if desc.get("lang") == "en":
                            result["description"] = desc.get("value", "")
                            break
                
                # Get CVSS score and severity (try v3.1 first, fall back to v2)
                if vuln.get("metrics", {}).get("cvssMetricV31"):
                    cvss_data = vuln["metrics"]["cvssMetricV31"][0].get("cvssData", {})
                    result["score"] = str(cvss_data.get("baseScore", ""))
                    result["severity"] = cvss_data.get("baseSeverity", "")
                elif vuln.get("metrics", {}).get("cvssMetricV2"):
                    cvss_data = vuln["metrics"]["cvssMetricV2"][0].get("cvssData", {})
                    result["score"] = str(cvss_data.get("baseScore", ""))
                    result["severity"] = vuln["metrics"]["cvssMetricV2"][0].get("baseSeverity", "")
            
            # Cache the result
            self.cache.set(cache_key, result)
        
        except requests.exceptions.RequestException as e:
            logging.warning(f"Error getting vulnerability details for {cve_id}: {e}")
        except Exception as e:
            logging.warning(f"Error processing vulnerability details for {cve_id}: {e}")
        
        return result