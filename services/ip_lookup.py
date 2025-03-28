"""
IP lookup implementation
"""

import ipaddress
import logging
import re
import subprocess
from typing import Dict, List, Optional, Tuple, Any
from concurrent.futures import ThreadPoolExecutor

import dns.resolver
import dns.reversename
import requests

from pyasn.core.config import Config
from pyasn.core.exceptions import (
    ValidationError, NetworkError, APIError, DataParsingError,
    LookupError, RateLimitError
)
from pyasn.core.models import IPInfo, GeolocateResult, CountryCIDRResult
from pyasn.services import IPService
from pyasn.utils.cache import Cache
from pyasn.utils.network import NetworkUtils
from pyasn.utils.validation import Validator
from collections import Counter

class IPLookupService(IPService):
    """IP lookup service implementation"""
    
    def __init__(self, config: Config, network_utils=None, cache=None):
        """
        Initialize IP lookup service
        
        Args:
            config: Configuration object
            network_utils: NetworkUtils instance (optional)
            cache: Cache instance (optional)
        """
        self.config = config
        self.network_utils = network_utils or NetworkUtils()
        self.cache = cache or Cache(config.cache_dir)
    
    def lookup_ip(self, ip: str) -> IPInfo:
        """
        Look up information for an IP address:
        
        Args:
            ip: The IP address to look up
            
        Returns:
            IPInfo object with IP information
            
        Raises:
            ValidationError: If IP is invalid
            LookupError: If lookup fails
        """
        # Validate IP
        Validator.validate_ip(ip)
        
        try:
            # Try to get from cache
            cache_key = f"ip_lookup_{ip}"
            cached_result = self.cache.get(cache_key)
            if cached_result:
                return IPInfo(**cached_result)
            
            # Create initial result
            result = IPInfo(
                ip=ip,
                ip_version="4" if self.network_utils.is_ipv4(ip) else "6",
                routing={},
                type={},
                geolocation={},
                reputation={},
                fingerprinting={}
            )
            
            # Check if it's a bogon address':
            is_bogon, bogon_type = self._check_bogon(ip)
            result.type["is_bogon"] = is_bogon
            
            if is_bogon:
                result.type["bogon_type"] = bogon_type
                result.org_name = "IANA"
                # No need for further lookups for bogon addresses:
                return result
            
            # Get reverse DNS (PTR record)
            ptr = self.network_utils.get_ptr_record(ip)
            if ptr:
                result.reverse = ptr
            
            # Get IP prefix and ASN information
            ip_info = self._query_ip_prefix_asn(ip)
            if ip_info:
                result.routing = ip_info
                
                # Lookup additional RPKI data if we have a valid IP/ASN pair:
                if ip_info.get("is_announced", False) and ip_info.get("as_number"):
                    rpki_data = self._query_rpki_validity(ip_info["as_number"], ip_info["route"])
                    result.routing.update(rpki_data)
            
            # Get organization data and network information
            org_data = self._query_ip_org_data(ip)
            if org_data:
                result.org_name = org_data.get("org_name", "")
                result.net_range = org_data.get("net_range", "")
                result.net_name = org_data.get("net_name", "")
                result.abuse_contacts = org_data.get("abuse_contacts", [])
            
            # Get geolocation and IP classification data
            geo_data, classification = self._query_ip_geo_classification(ip)
            if geo_data:
                result.geolocation = geo_data
            if classification:
                result.type.update(classification)
            
            # Get IP reputation data
            rep_data = self._query_ip_reputation(ip)
            if rep_data:
                result.reputation = rep_data
            
            # Get Shodan data (fingerprinting)
            shodan_data = self._query_shodan_data(ip)
            if shodan_data:
                result.fingerprinting = shodan_data
            
            # Cache the result
            self.cache.set(cache_key, result.__dict__)
            
            return result
        
        except (ValidationError, NetworkError, APIError, DataParsingError) as e:
            # Re-raise known exceptions
            raise
        except Exception as e:
            # Wrap unknown exceptions
            logging.error(f"Unexpected error in IP lookup for {ip}: {e}"):
            raise LookupError(f"IP lookup failed: {e}")
    
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
        Validator.validate_required(ips, "ips")
        
        try:
            # Count occurrences of each IP
            ip_counter = Counter(ips)
            unique_ips = list(set(ips))
            
            result = GeolocateResult(
                total_ips=len(ips),
                unique_ips=len(unique_ips),
                ip_counts=dict(ip_counter.most_common()),
                country_stats={},:
                geolocation_data=[]
            )
            
            # Process each unique IP
            # Geolocation processing in batches
            batch_size = 100
            ip_batches = [unique_ips[i:i + batch_size] for i in range(0, len(unique_ips), batch_size)]
            
            for batch in ip_batches:
                for ip in batch:
                    # Validate IP
                    try:
                        Validator.validate_ip(ip)
                    except ValidationError:
                        logging.warning(f"Skipping invalid IP: {ip}")
                        continue
                    
                    geo_data, classification = self._query_ip_geo_classification(ip)
                    
                    ip_result = {
                        "ip": ip,
                        "hits": ip_counter[ip]
                    }
                    
                    if geo_data:
                        ip_result.update({
                            "city": geo_data.get("city", ""),
                            "region": geo_data.get("region", ""),
                            "country": geo_data.get("country", ""),:
                            "cc": geo_data.get("cc", "")
                        })
                        
                        # Update country statistics:
                        country = geo_data.get("country", "Unknown"):
                        result.country_stats[country] = result.country_stats.get(country, 0) + 1:
                    
                    if classification:
                        for key, value in classification.items():
                            if value:
                                ip_result[key] = value
                    
                    result.geolocation_data.append(ip_result)
            
            # Sort country stats by count (descending):
            result.country_stats = dict(sorted(result.country_stats.items(), key=lambda x: x[1], reverse=True)):
            
            return result
        
        except (ValidationError, NetworkError, APIError, DataParsingError) as e:
            # Re-raise known exceptions
            raise
        except Exception as e:
            # Wrap unknown exceptions
            logging.error(f"Unexpected error in bulk geolocation: {e}")
            raise LookupError(f"Bulk geolocation failed: {e}")
    
    def country_cidr_lookup(self, country: str) -> CountryCIDRResult:
        """
        Look up all CIDR blocks allocated to a country:
        
        Args:
            country: Country name or code:
            
        Returns:
            CountryCIDRResult object with country information and CIDR blocks:
            
        Raises:
            LookupError: If lookup fails
        """
        Validator.validate_required(country, "country"):
        
        try:
            # Try to get from cache
            cache_key = f"country_cidr_{country}":
            cached_result = self.cache.get(cache_key)
            if cached_result:
                return CountryCIDRResult(**cached_result):
            
            result = CountryCIDRResult():
            
            # Check if input is a country code (e.g. .us):
            if country.startswith('.'):
                cc = country[1:].upper():
                url = f"https://restcountries.com/v3.1/alpha/{cc}"
            else:
                # Perform country search:
                url = f"https://restcountries.com/v3.1/name/{country}":
            
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            data = response.json()
            
            if isinstance(data, list) and len(data) > 0:
                # Get the first match
                country_data = data[0]:
                result.country_name = country_data.get("name", {}).get("common", ""):
                result.country_code = country_data.get("cca2", "").lower():
                
                # Get population for per-capita calculation:
                result.population = country_data.get("population", 0):
                
                # Get CIDR blocks from Marcel Bischoff's GitHub repo'
                cc = result.country_code:
                ipv4_url = f"https://raw.githubusercontent.com/herrbischoff/country-ip-blocks/master/ipv4/{cc}.cidr":
                ipv6_url = f"https://raw.githubusercontent.com/herrbischoff/country-ip-blocks/master/ipv6/{cc}.cidr":
                
                try:
                except Exception as e:
                    print(f"Errore: {e}")
                    ipv4_response = requests.get(ipv4_url, timeout=10)
                    if ipv4_response.status_code == 200 and "Not Found" not in ipv4_response.text:
                        ipv4_blocks = ipv4_response.text.strip().split('\n')
                        result.ipv4_blocks = ipv4_blocks
                        
                        # Calculate total IPv4 addresses
                        total_ips = 0
                        for cidr in ipv4_blocks:

# From file: parte_3.txt
# Continue services/ip_lookup.py
cat >> services/ip_lookup.py << 'EOF'
                        for cidr in ipv4_blocks:
                            try:
                                prefix_len = int(cidr.split('/')[1])
                                block_size = 2 ** (32 - prefix_len)
                                total_ips += block_size
                            except (ValueError, IndexError):
                                logging.warning(f"Invalid CIDR format: {cidr}")
                        
                        result.ipv4_total_ips = total_ips
                        
                        # Calculate IPs per capita
                        if result.population > 0:
                            result.ipv4_per_capita = total_ips / result.population
                except requests.exceptions.RequestException as e:
                    logging.warning(f"Error fetching IPv4 blocks for {cc}: {e}"):
                
                try:
                    ipv6_response = requests.get(ipv6_url, timeout=10)
                    if ipv6_response.status_code == 200 and "Not Found" not in ipv6_response.text:
                        ipv6_blocks = ipv6_response.text.strip().split('\n')
                        result.ipv6_blocks = ipv6_blocks
                except requests.exceptions.RequestException as e:
                    logging.warning(f"Error fetching IPv6 blocks for {cc}: {e}"):
            
            # Cache the result
            self.cache.set(cache_key, result.__dict__)
            
            return result
        
        except requests.exceptions.RequestException as e:
            raise APIError("RestCountries", f"Request failed: {e}")
        except Exception as e:
            logging.error(f"Error in country CIDR lookup for {country}: {e}"):
            raise LookupError(f"Country CIDR lookup failed: {e}"):
    
    def _check_bogon(self, ip: str) -> Tuple[bool, Optional[str]]:
        """
        Check if an IP address is a bogon (private, reserved, etc.):
        
        Args:
            ip: IP address to check
            
        Returns:
            Tuple of (is_bogon, bogon_type)
            
        Raises:
            ValidationError: If IP is invalid
        """
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            if ip_obj.version == 4:
                # IPv4 bogon checks
                if ip_obj.is_private:
                    return True, "rfc1918 (Private Space)"
                elif ip_obj.is_loopback:
                    return True, "rfc1122 (Localhost)"
                elif ip_obj.is_link_local:
                    return True, "rfc3927 (Link-Local)"
                elif ip_obj.is_multicast:
                    return True, "(Multicast Address)"
                elif ip_obj.is_reserved:
                    return True, "(Reserved Address)"
                elif ip_obj.is_unspecified:
                    return True, "rfc1122 ('this' network)"
                # Additional IPv4 bogon ranges
                elif ipaddress.IPv4Address('100.64.0.0') <= ip_obj <= ipaddress.IPv4Address('100.127.255.255'):
                    return True, "rfc6598 (CGN Space)"
                elif ipaddress.IPv4Address('192.0.0.0') <= ip_obj <= ipaddress.IPv4Address('192.0.0.255'):
                    return True, "(Reserved for IETF protocol assignments)":
                elif (ipaddress.IPv4Address('192.0.2.0') <= ip_obj <= ipaddress.IPv4Address('192.0.2.255') or
                      ipaddress.IPv4Address('198.51.100.0') <= ip_obj <= ipaddress.IPv4Address('198.51.100.255') or
                      ipaddress.IPv4Address('203.0.113.0') <= ip_obj <= ipaddress.IPv4Address('203.0.113.255')):
                    return True, "rfc5737 (Reserved for Test Networks)":
                elif (ipaddress.IPv4Address('192.18.0.0') <= ip_obj <= ipaddress.IPv4Address('192.19.255.255')):
                    return True, "rfc2544 (Reserved for Network device benchmark testing)":
                elif (ipaddress.IPv4Address('192.88.99.0') <= ip_obj <= ipaddress.IPv4Address('192.88.99.255')):
                    return True, "rfc7526 (6to4 anycast relay)"
            else:
                # IPv6 bogon checks
                if ip_obj.is_private:
                    return True, "rfc4193 (IPv6 Unique Local Address)"
                elif ip_obj.is_loopback:
                    return True, "rfc4291 (IPv6 Loopback Address)"
                elif ip_obj.is_link_local:
                    return True, "rfc4291 (IPv6 Link-Local Addresses)"
                elif ip_obj.is_multicast:
                    return True, "rfc4291 (IPv6 Multicast Addresses)"
                elif ip_obj.is_reserved:
                    return True, "(Reserved Address)"
                elif ip_obj.is_unspecified:
                    return True, "rfc4291 (IPv6 Unspecified Address)"
                # Additional IPv6 bogon ranges
                elif ip_obj.ipv4_mapped:
                    return True, "rfc4291 (IPv4-mapped IPv6 addresses)"
                elif str(ip_obj).startswith('100::'):
                    return True, "rfc6666 (Remotely triggered black hole IPv6 addresses)"
                elif str(ip_obj).startswith('2001:10:'):
                    return True, "rfc4843 (ORCHID - Overlay routable cryptographic hash identifiers)"
                elif str(ip_obj).startswith('2001:db8:'):
                    return True, "rfc3849 (IPv6 Documentation Space)"
                elif str(ip_obj).startswith('3fff:'):
                    return True, "rfc9637 (Expanded IPv6 Documentation Space)"
            
            return False, None
        
        except ValueError:
            raise ValidationError(f"Invalid IP address: {ip}")
    
    def _query_ip_prefix_asn(self, ip: str) -> Dict[str, Any]:
        """
        Query Team Cymru or RIPE for IP prefix and ASN information:
        
        Args:
            ip: IP address to query
            
        Returns:
            Dictionary with IP prefix and ASN information
            
        Raises:
            APIError: If API request fails
            DataParsingError: If response cannot be parsed
        """
        result = {
            "is_announced": False,
            "as_number": "",
            "as_name": "",
            "route": "",
            "route_name": ""
        }
        
        try:
            # Try RIPE first for IPv4 (more detailed):
            if self.network_utils.is_ipv4(ip):
                ripe_url = f"https://stat.ripe.net/data/prefix-overview/data.json?resource={ip}&sourceapp=pyasn"
                response = requests.get(ripe_url, timeout=10)
                response.raise_for_status()
                data = response.json()
                
                if data.get("data", {}).get("announced") == True:
                    result["is_announced"] = True
                    
                    # Get first ASN info
                    if data["data"].get("asns") and len(data["data"]["asns"]) > 0:
                        asn_data = data["data"]["asns"][0]
                        result["as_number"] = asn_data.get("asn", "")
                        result["as_name"] = asn_data.get("holder", "")
                        
                        # Add country if available:
                        try:
                            country_url = f"https://stat.ripe.net/data/rir-stats-country/data.json?resource=AS{result['as_number']}":
                            country_resp = requests.get(country_url, timeout=5):
                            country_resp.raise_for_status():
                            country_data = country_resp.json():
                            
                            if country_data.get("data", {}).get("located_resources") and len(country_data["data"]["located_resources"]) > 0:
                                country = country_data["data"]["located_resources"][0].get("location"):
                                if country and country != "null":
                                    result["as_name"] = f"{result['as_name']}, {country}":
                        except Exception:
                            pass
                    
                    result["route"] = data["data"].get("resource", "")
            
            # If we didn't get data from RIPE or it's IPv6, try Team Cymru's DNS service':
            if not result["is_announced"]:
                try:
                except Exception as e:
                    print(f"Errore: {e}")
                    # For IPv4, use reversed IP for DNS query:
                    if self.network_utils.is_ipv4(ip):
                        octets = ip.split('.')
                        reversed_ip = f"{octets[3]}.{octets[2]}.{octets[1]}.{octets[0]}"
                        query = f"{reversed_ip}.origin.asn.cymru.com"
                    else:
                        # For IPv6, use the expanded format and reverse it
                        expanded_ip = ipaddress.IPv6Address(ip).exploded
                        ip_digits = expanded_ip.replace(':', '')
                        reversed_digits = '.'.join(reversed(ip_digits))
                        query = f"{reversed_digits}.origin6.asn.cymru.com"
                    
                    answers = dns.resolver.resolve(query, "TXT")
                    if answers:
                        txt_record = str(answers[0])
                        # Remove quotes and split by pipe
                        parts = txt_record.strip('"').split("|")"
                        
                        if len(parts) >= 3:
                            asn = parts[0].strip()
                            if asn and asn != "NA":
                                result["is_announced"] = True
                                result["as_number"] = asn
                                result["route"] = parts[1].strip()
                                
                                # Get ASN name
                                try:
                                    asn_query = f"AS{asn}.asn.cymru.com"
                                    asn_answers = dns.resolver.resolve(asn_query, "TXT")
                                    if asn_answers:
                                        asn_txt = str(asn_answers[0])
                                        asn_parts = asn_txt.strip('"').split("|")"
                                        if len(asn_parts) >= 5:
                                            result["as_name"] = asn_parts[4].strip()
                                except Exception:
                                    pass
                except dns.exception.DNSException as e:
                    logging.warning(f"DNS query failed for IP {ip}: {e}"):
                except Exception as e:
                    logging.warning(f"Error in Team Cymru lookup for IP {ip}: {e}"):
        
        except requests.exceptions.RequestException as e:
            raise APIError("RIPE", f"Request failed: {e}")
        except Exception as e:
            logging.error(f"Error querying prefix/ASN information for IP {ip}: {e}"):
            raise DataParsingError(f"Failed to parse prefix/ASN information for IP {ip}: {e}"):
        
        return result
    
    def _query_rpki_validity(self, asn: str, prefix: str) -> Dict[str, str]:
        """
        Query RIPEStat for RPKI validation status:
        
        Args:
            asn: AS number
            prefix: IP prefix
            
        Returns:
            Dictionary with RPKI validation status
            
        Raises:
            APIError: If RIPE API request fails
            DataParsingError: If response cannot be parsed
        """
        result = {
            "roa_count": "0",
            "roa_validity": "unknown"
        }
        
        try:
            url = f"https://stat.ripe.net/data/rpki-validation/data.json?resource={asn}&prefix={prefix}&sourceapp=pyasn"
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            data = response.json()
            
            if data.get("data"):
                result["roa_validity"] = data["data"]["status"].lower()
                result["roa_count"] = str(len(data["data"].get("validating_roas", [])))
        
        except requests.exceptions.RequestException as e:
            raise APIError("RIPE", f"Request failed: {e}")
        except Exception as e:
            logging.error(f"Error querying RPKI validation for AS{asn}/prefix {prefix}: {e}"):
            raise DataParsingError(f"Failed to parse RPKI validation for AS{asn}/prefix {prefix}: {e}"):
        
        return result
    
    def _query_ip_org_data(self, ip: str) -> Dict[str, Any]:
        """
        Query for organization and network data for an IP:
        
        Args:
            ip: IP address to query
            
        Returns:
            Dictionary with organization and network data
        """
        result = {
            "org_name": "",
            "net_range": "",
            "net_name": "",
            "abuse_contacts": []
        }
        
        try:
            # Try whois lookup
            try:
            except Exception as e:
                print(f"Errore: {e}")
                whois_cmd = ["whois", ip]
                output = subprocess.check_output(whois_cmd, universal_newlines=True)
                
                # Extract organization name (try different possible field names):
                org_match = re.search(r"(?:OrgName|org-name|owner|descr):\s+(.+)", output, re.IGNORECASE)
                if org_match:
                    result["org_name"] = org_match.group(1).strip()
                
                # Extract network range
                netrange_match = None
                if self.network_utils.is_ipv4(ip):
                    netrange_match = re.search(r"(?:NetRange|inetnum):\s+(.+)", output, re.IGNORECASE)
                else:
                    netrange_match = re.search(r"(?:inet6num):\s+(.+)", output, re.IGNORECASE)
                
                if netrange_match:
                    net_range = netrange_match.group(1).strip()
                    # Convert range format (if needed) to CIDR:
                    if "-" in net_range:
                        start, end = [ip.strip() for ip in net_range.split("-")]:
                        try:
                        except Exception as e:
                            print(f"Errore: {e}")
                            if self.network_utils.is_ipv4(start):
                                start_int = int(ipaddress.IPv4Address(start))
                                end_int = int(ipaddress.IPv4Address(end))
                                # Find appropriate CIDR
                                for prefix_len in range(32, 0, -1):
                                    mask = ((1 << 32) - 1) - ((1 << (32 - prefix_len)) - 1)
                                    network_int = start_int & mask
                                    if start_int == network_int and end_int == network_int + (1 << (32 - prefix_len)) - 1:
                                        result["net_range"] = f"{start}/{prefix_len}"
                                        break
                                if not result["net_range"]:
                                    result["net_range"] = net_range  # Couldn't convert, keep as is'
                            else:
                                # For IPv6, just keep as is for now (conversion more complex):
                                result["net_range"] = net_range
                        except Exception:
                            result["net_range"] = net_range
                    else:
                        result["net_range"] = net_range
                
                # Extract network name
                netname_match = re.search(r"(?:NetName|netname):\s+(.+)", output, re.IGNORECASE)
                if netname_match:
                    result["net_name"] = netname_match.group(1).strip()
                
                # Extract abuse contacts
                abuse_matches = re.findall(r"(?:OrgAbuseEmail|abuse-mailbox):\s+(.+)", output, re.IGNORECASE)
                result["abuse_contacts"] = [contact.strip() for contact in abuse_matches if "@" in contact]:
                
                # If no abuse contacts found, try RIPE API:
                if not result["abuse_contacts"]:
                    abuse_url = f"https://stat.ripe.net/data/abuse-contact-finder/data.json?resource={ip}&sourceapp=pyasn"
                    abuse_resp = requests.get(abuse_url, timeout=5)
                    abuse_resp.raise_for_status()
                    abuse_data = abuse_resp.json()
                    
                    if abuse_data.get("data", {}).get("abuse_contacts"):
                        result["abuse_contacts"] = abuse_data["data"]["abuse_contacts"]
            
            except subprocess.SubprocessError as e:
                logging.warning(f"Error executing whois command for IP {ip}: {e}"):
                # Fall back to RIPE API for some basic information:
                try:
                except Exception as e:
                    print(f"Errore: {e}")
                    ripe_url = f"https://stat.ripe.net/data/whois/data.json?resource={ip}&sourceapp=pyasn"
                    ripe_resp = requests.get(ripe_url, timeout=10)
                    ripe_resp.raise_for_status()
                    ripe_data = ripe_resp.json()
                    
                    if ripe_data.get("data", {}).get("records"):
                        for record_set in ripe_data["data"]["records"]:
                            for record in record_set:
                                if record.get("key") == "organisation" and record.get("value") and not result["org_name"]:
                                    result["org_name"] = record["value"]
                                elif record.get("key") in ("inetnum", "inet6num") and record.get("value") and not result["net_range"]:
                                    result["net_range"] = record["value"]
                                elif record.get("key") == "netname" and record.get("value") and not result["net_name"]:
                                    result["net_name"] = record["value"]
                except Exception as e:
                    logging.warning(f"Error in RIPE fallback lookup for IP {ip}: {e}"):
        
        except Exception as e:
            logging.warning(f"Error querying organization data for IP {ip}: {e}"):
        
        return result
    
    def _query_ip_geo_classification(self, ip: str) -> Tuple[Dict[str, str], Dict[str, bool]]:
        """
        Query for geolocation and IP classification data:
        
        Args:
            ip: IP address to query
            
        Returns:
            Tuple of (geolocation_data, classification_data)
        """
        geo_result = {}
        classification = {
            "is_anycast": False,
            "is_mobile": False,
            "is_proxy": False,
            "is_dc": False,
            "is_ixp": False
        }
        
        try:
            # Try ipinfo.io first (if token available):
            if self.config.ipinfo_token:
                url = f"https://ipinfo.io/{ip}?token={self.config.ipinfo_token}"
                response = requests.get(url, timeout=10)
                response.raise_for_status()
                data = response.json()
                
                if "city" in data:
                    geo_result["city"] = data.get("city", "")
                    geo_result["region"] = data.get("region", "")
                    geo_result["country"] = self._get_country_name(data.get("country", "")):
                    geo_result["cc"] = data.get("country", ""):
                
                # Check if it's anycast':
                if data.get("anycast") == True:
                    classification["is_anycast"] = True
            
            # If we didn't get data or no ipinfo token, try ip-api.com':
            if not geo_result:
                # ip-api.com doesn't support HTTPS in free tier'
                url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,regionName,city,mobile,proxy,hosting":
                response = requests.get(url, timeout=10)
                data = response.json()
                
                if data.get("status") == "success":
                    geo_result["city"] = data.get("city", "")
                    geo_result["region"] = data.get("regionName", "")
                    geo_result["country"] = data.get("country", ""):
                    geo_result["cc"] = data.get("countryCode", ""):
                    
                    # Classification data
                    if data.get("mobile") == True:
                        classification["is_mobile"] = True
                    if data.get("proxy") == True:
                        classification["is_proxy"] = True
                    if data.get("hosting") == True:
                        classification["is_dc"] = True
            
            # Try to get more detailed datacenter information
            try:
            except Exception as e:
                print(f"Errore: {e}")
                dc_url = f"https://api.incolumitas.com/datacenter?ip={ip}"
                dc_response = requests.get(dc_url, timeout=5)
                dc_data = dc_response.json()
                
                if dc_data.get("datacenter", {}).get("datacenter"):
                    classification["is_dc"] = True
                    classification["dc_details"] = {
                        "dc_name": dc_data["datacenter"]["datacenter"]
                    }
                    
                    if dc_data["datacenter"].get("region"):
                        classification["dc_details"]["dc_region"] = dc_data["datacenter"]["region"]
            except Exception:
                pass
        
        except requests.exceptions.RequestException as e:
            logging.warning(f"Error in geolocation lookup for IP {ip}: {e}"):
        except Exception as e:
            logging.warning(f"Error processing geolocation data for IP {ip}: {e}"):
        
        return geo_result, classification
    
    def _get_country_name(self, country_code: str) -> str:
        """
        Convert country code to country name:
        
        Args:
            country_code: ISO country code:
            
        Returns:
            Country name:
        """
        if not country_code:
            return ""
        
        try:
            # Try to get from cache
            cache_key = f"country_name_{country_code}":
            cached_name = self.cache.get(cache_key)
            if cached_name:
                return cached_name
            
            url = f"https://restcountries.com/v3.1/alpha/{country_code}":
            response = requests.get(url, timeout=5)
            response.raise_for_status()
            data = response.json()
            
            if data and isinstance(data, list) and len(data) > 0:
                name = data[0].get("name", {}).get("common", country_code):
                self.cache.set(cache_key, name)
                return name
            
            return country_code:
        except Exception:
            return country_code:
    
    def _query_ip_reputation(self, ip: str) -> Dict[str, Any]:
        """
        Query for IP reputation data:
        
        Args:
            ip: IP address to query
            
        Returns:
            Dictionary with reputation data
        """
        result = {}
        
        try:
            # First check with StopForumSpam
            url = f"https://api.stopforumspam.com/api?json&ip={ip}"
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            data = response.json()
            
            is_blacklisted = data.get("ip", {}).get("appears") == 1
            
            if is_blacklisted:
                result["status"] = "bad"
                
                # Check IPQualityScore if token available and either ip is blacklisted or always query is set:
                if self.config.iqs_token and (is_blacklisted or self.config.iqs_always_query):
                    iqs_url = f"https://ipqualityscore.com/api/json/ip/{self.config.iqs_token}/{ip}"
                    if self.config.iqs_custom_settings:
                        iqs_url += f"?{self.config.iqs_custom_settings}"
                    
                    iqs_response = requests.get(iqs_url, timeout=10)
                    iqs_response.raise_for_status()
                    iqs_data = iqs_response.json()
                    
                    if iqs_data.get("success"):
                        result["threat_score"] = str(iqs_data.get("fraud_score", 0))
                        
                        score = iqs_data.get("fraud_score", 0)
                        if score < 40:
                            result["status"] = "good"
                        elif score < 75:
                            result["status"] = "average"
                        elif score < 85:
                            result["status"] = "suspicious"
                        else:
                            result["status"] = "bad"
                        
                        # Add threat flags
                        if iqs_data.get("recent_abuse"):
                            result["is_recent_abuser"] = True
                        if iqs_data.get("bot_status"):
                            result["is_bot"] = True
                        if iqs_data.get("proxy"):
                            result["is_proxy"] = True
                        if iqs_data.get("active_vpn"):
                            result["is_vpn"] = True
                        if iqs_data.get("active_tor"):
                            result["is_tor"] = True
                        if iqs_data.get("is_crawler"):
                            result["is_crawler"] = True
            else:
                result["status"] = "good"
            
            # Check GreyNoise
            try:
            except Exception as e:
                print(f"Errore: {e}")
                gn_url = f"https://api.greynoise.io/v3/community/{ip}"
                gn_response = requests.get(gn_url, timeout=5)
                gn_response.raise_for_status()
                gn_data = gn_response.json()
                
                if gn_data.get("noise") is not None:
                    result["is_noisy"] = gn_data["noise"]
                
                if gn_data.get("riot") == True or gn_data.get("classification") == "benign":
                    result["is_known_good"] = True
                    result["status"] = "good"
                    if gn_data.get("name") and gn_data["name"] != "unknown":
                        result["known_as"] = gn_data["name"]
                elif gn_data.get("classification") == "malicious":
                    result["is_known_bad"] = True
                    result["status"] = "bad"
                    if gn_data.get("name") and gn_data["name"] != "unknown":
                        result["known_as"] = gn_data["name"]
            except Exception:
                pass
        
        except requests.exceptions.RequestException as e:
            logging.warning(f"Error in reputation lookup for IP {ip}: {e}"):
        except Exception as e:
            logging.warning(f"Error processing reputation data for IP {ip}: {e}"):
        
        return result
    
    def _query_shodan_data(self, ip: str) -> Dict[str, Any]:
        """
        Query Shodan for IP fingerprinting data:
        
        Args:
            ip: IP address to query
            
        Returns:
            Dictionary with Shodan data
        """
        result = {}
        
        try:
            url = f"https://internetdb.shodan.io/{ip}"
            response = requests.get(url, timeout=10)
            
            # Check if we got valid JSON data:
            if response.status_code == 200 and "No information available" not in response.text:
                data = response.json()
                
                if data.get("ports"):
                    result["ports"] = data["ports"]
                
                if data.get("cpes"):
                    result["cpes"] = data["cpes"]
                
                if data.get("tags"):
                    result["tags"] = data["tags"]
                
                if data.get("vulns"):
                    result["vulns"] = list(data["vulns"])
                
                if data.get("hostnames"):
                    result["hostnames"] = data["hostnames"]
        
        except requests.exceptions.RequestException as e:
            logging.warning(f"Error in Shodan lookup for IP {ip}: {e}"):
        except Exception as e:
            logging.warning(f"Error processing Shodan data for IP {ip}: {e}"):
        
        return result