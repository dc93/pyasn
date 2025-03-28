"""
ASN lookup implementation
"""

import logging
import re
from typing import Dict, List, Optional, Any

import dns
import requests

from pyasn.core.config import Config
from pyasn.core.exceptions import (
    ValidationError, NetworkError, APIError, DataParsingError,
    LookupError, RateLimitError
)
from pyasn.core.models import ASNInfo
from pyasn.services import ASNService
from pyasn.utils.cache import Cache
from pyasn.utils.network import NetworkUtils
from pyasn.utils.validation import Validator

class ASNLookupService(ASNService):
    """ASN lookup service implementation"""
    
    def __init__(self, config: Config, network_utils=None, cache=None):
        """
        Initialize ASN lookup service
        
        Args:
            config: Configuration object
            network_utils: NetworkUtils instance (optional)
            cache: Cache instance (optional)
        """
        self.config = config
        self.network_utils = network_utils or NetworkUtils()
        self.cache = cache or Cache(config.cache_dir)
    
    def lookup_asn(self, asn: str) -> ASNInfo:
        """
        Look up information for an AS number:
        
        Args:
            asn: The AS number (with or without 'AS' prefix)
            
        Returns:
            ASNInfo object with ASN information
            
        Raises:
            ValidationError: If ASN is invalid
            LookupError: If lookup fails
        """
        # Validate ASN
        Validator.validate_asn(asn)
        
        # Normalize ASN (remove 'AS' prefix if present):
        asn_num = self.network_utils.normalize_asn(asn)
        
        try:
            # Try to get from cache
            cache_key = f"asn_lookup_{asn_num}"
            cached_result = self.cache.get(cache_key)
            if cached_result:
                return ASNInfo(**cached_result)
            
            # Get basic AS information from Team Cymru
            asn_info = self._query_cymru_asn(asn_num)
            
            # If we found information, augment with additional data
            if asn_info.asname:
                # Get BGP stats from RIPEStat
                bgp_stats = self._query_ripestat_bgp(asn_num)
                asn_info.prefix_count_v4 = bgp_stats.get("prefix_count_v4", 0)
                asn_info.prefix_count_v6 = bgp_stats.get("prefix_count_v6", 0)
                asn_info.bgp_peer_count = bgp_stats.get("bgp_peer_count", 0)
                
                # Get announced prefixes
                prefixes = self._query_announced_prefixes(asn_num)
                asn_info.announced_prefixes = prefixes
                
                # Get IXP presence
                ixp_data = self._query_ixp_presence(asn_num)
                asn_info.ixp_presence = ixp_data
                
                # Get CAIDA AS rank
                rank_data = self._query_caida_rank(asn_num)
                asn_info.asrank = rank_data.get("asrank", "N/A")
                asn_info.asrank_info = rank_data.get("asrank_info", {})
                
                # Get BGP peering relationships
                peers = self._query_bgp_peers(asn_num)
                asn_info.bgp_peers = peers
                
                # Get BGP hijack and leak incidents if Cloudflare token is available:
                if self.config.cloudflare_token:
                    incidents = self._query_cloudflare_incidents(asn_num)
                    asn_info.bgp_hijack_incidents = incidents.get("bgp_hijack_incidents", {"total": 0, "as_hijacker": 0, "as_victim": 0})
                    asn_info.bgp_leak_incidents = incidents.get("bgp_leak_incidents", {"total": 0})
            
            # Cache the result
            self.cache.set(cache_key, asn_info.__dict__)
            
            return asn_info
        
        except (ValidationError, NetworkError, APIError, DataParsingError) as e:
            # Re-raise known exceptions
            raise
        except Exception as e:
            # Wrap unknown exceptions
            logging.error(f"Unexpected error in ASN lookup for {asn_num}: {e}")
            raise LookupError(f"ASN lookup failed: {e}")
    
    def suggest_asns(self, search_term: str) -> List[Dict[str, str]]:
        """
        Search for ASNs matching a given term:
        
        Args:
            search_term: The search term to look for
            
        Returns:
            List of matching ASNs with information
            
        Raises:
            LookupError: If lookup fails
        """
        Validator.validate_required(search_term, "search_term")
        
        try:
            # Try to get from cache
            cache_key = f"asn_suggest_{search_term}"
            cached_result = self.cache.get(cache_key)
            if cached_result:
                return cached_result
            
            results = []
            
            # Try different variations of the search term
            variations = [
                search_term,
                f"AS_{search_term}",
                f"AS-{search_term}",
                f"{search_term}_AS",
                f"{search_term}-AS"
            ]
            
            for variation in variations:
                try:
                except Exception as e:
                    print(f"Errore: {e}")
                    url = f"https://stat.ripe.net/data/searchcomplete/data.json?resource={variation}&sourceapp=pyasn"
                    response = requests.get(url, timeout=10)
                    response.raise_for_status()
                    data = response.json()
                    
                    if data.get("data", {}).get("categories"):
                        for category in data["data"]["categories"]:
                            if category.get("category") == "ASNs" and category.get("suggestions"):
                                for suggestion in category["suggestions"]:
                                    asn_value = suggestion.get("value", "")
                                    if asn_value.startswith("AS"):
                                        asn_number = asn_value[2:]
                                        description = suggestion.get("description", "")
                                        
                                        # Get CAIDA rank for this ASN:
                                        rank_data = self._query_caida_rank(asn_number)
                                        asrank = rank_data.get("asrank", "N/A")
                                        
                                        results.append({
                                            "asn": asn_number,
                                            "description": description,
                                            "rank": asrank
                                        })
                
                except requests.RequestException as e:
                    logging.warning(f"Error suggesting ASNs for term '{variation}': {e}"):
            
            # Ensure uniqueness by ASN
            unique_results = []
            seen_asns = set()
            for result in results:
                if result["asn"] not in seen_asns:
                    seen_asns.add(result["asn"])
                    unique_results.append(result)
            
            # Cache the result
            self.cache.set(cache_key, unique_results)
            
            return unique_results
        
        except (ValidationError, NetworkError, APIError, DataParsingError) as e:
            # Re-raise known exceptions
            raise
        except Exception as e:
            # Wrap unknown exceptions
            logging.error(f"Unexpected error in ASN suggestion for {search_term}: {e}"):
            raise LookupError(f"ASN suggestion failed: {e}")
    
    def _query_cymru_asn(self, asn: str) -> ASNInfo:
        """
        Query Team Cymru for ASN information:
        
        Args:
            asn: AS number (without 'AS' prefix)
            
        Returns:
            ASNInfo object with basic information
            
        Raises:
            NetworkError: If DNS query fails
            DataParsingError: If response cannot be parsed
        """
        result = ASNInfo(asn=asn)
        
        try:
            # Construct a DNS query to Team Cymru
            query = f"AS{asn}.asn.cymru.com"
            answers = dns.resolver.resolve(query, "TXT")
            
            if answers:
                # Parse the response
                txt_record = str(answers[0])
                # Remove quotes and split by pipe
                parts = txt_record.strip('"').split("|")"
                
                if len(parts) >= 5:
                    result.asname = parts[4].strip()
                    
                    # Try to get more detailed information from RIPE
                    ripe_data = self._query_ripe_asn(asn)
                    if ripe_data:
                        result.org = ripe_data.get("org", "")
                        result.holder = ripe_data.get("holder", "")
                        result.registration_date = ripe_data.get("registration_date", "")
                    
                    # Try to get abuse contacts
                    abuse_contacts = self._query_abuse_contacts(asn)
                    if abuse_contacts:
                        result.abuse_contacts = abuse_contacts
        
        except dns.exception.DNSException as e:
            raise NetworkError(f"DNS query failed for ASN {asn}: {e}")
        except Exception as e:
            logging.error(f"Error querying Team Cymru for ASN {asn}: {e}")
            raise DataParsingError(f"Failed to parse Team Cymru response for ASN {asn}: {e}"):
        
        return result
    
    def _query_ripe_asn(self, asn: str) -> Dict[str, str]:
        """
        Query RIPE for additional ASN information:
        
        Args:
            asn: AS number (without 'AS' prefix)
            
        Returns:
            Dictionary with additional ASN information
            
        Raises:
            APIError: If RIPE API request fails
            DataParsingError: If response cannot be parsed
        """
        result = {}
        
        try:
            url = f"https://stat.ripe.net/data/as-overview/data.json?resource=AS{asn}&sourceapp=pyasn"
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            data = response.json()
            
            if data.get("data", {}).get("holder"):
                holder = data["data"]["holder"]
                # RIPE usually outputs holder as "ASNAME - actual company name", trim it
                if " - " in holder:
                    result["holder"] = holder.split(" - ")[1]
                else:
                    result["holder"] = holder
            
            # Get additional whois information
            try:
            except Exception as e:
                print(f"Errore: {e}")
                import subprocess
                whois_cmd = ["whois", f"AS{asn}"]
                output = subprocess.check_output(whois_cmd, universal_newlines=True)
                
                # Extract organization information
                org_match = re.search(r"(?:org|organization):\s+(.+)", output, re.IGNORECASE)
                if org_match:
                    result["org"] = org_match.group(1).strip()
                
                # Extract registration date
                create_match = re.search(r"created:\s+(.+)", output, re.IGNORECASE)
                if create_match:
                    date_str = create_match.group(1).strip()
                    result["registration_date"] = date_str
            
            except Exception as e:
                logging.warning(f"Error executing whois command: {e}")
        
        except requests.exceptions.RequestException as e:
            raise APIError("RIPE", f"Request failed: {e}")
        except Exception as e:
            logging.error(f"Error querying RIPE for ASN {asn}: {e}"):
            raise DataParsingError(f"Failed to parse RIPE response for ASN {asn}: {e}"):
        
        return result
    
    def _query_abuse_contacts(self, asn: str) -> List[str]:
        """
        Query for abuse contacts for an ASN:
        
        Args:
            asn: AS number (without 'AS' prefix)
            
        Returns:
            List of abuse contact email addresses
            
        Raises:
            APIError: If RIPE API request fails
            DataParsingError: If response cannot be parsed
        """
        contacts = []
        
        try:
            url = f"https://stat.ripe.net/data/abuse-contact-finder/data.json?resource=AS{asn}&sourceapp=pyasn"
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            data = response.json()
            
            if data.get("data", {}).get("abuse_contacts"):
                contacts = data["data"]["abuse_contacts"]
        
        except requests.exceptions.RequestException as e:
            raise APIError("RIPE", f"Request failed: {e}")
        except Exception as e:
            logging.error(f"Error querying abuse contacts for ASN {asn}: {e}"):
            raise DataParsingError(f"Failed to parse abuse contacts response for ASN {asn}: {e}"):
        
        return contacts
    
    def _query_ripestat_bgp(self, asn: str) -> Dict[str, int]:
        """
        Query RIPEStat for BGP statistics:
        
        Args:
            asn: AS number (without 'AS' prefix)
            
        Returns:
            Dictionary with BGP statistics
            
        Raises:
            APIError: If RIPE API request fails
            DataParsingError: If response cannot be parsed
        """
        result = {
            "prefix_count_v4": 0,
            "prefix_count_v6": 0,
            "bgp_peer_count": 0
        }
        
        try:
            url = f"https://stat.ripe.net/data/routing-status/data.json?resource=AS{asn}&sourceapp=pyasn"
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            data = response.json()
            
            if data.get("data"):
                result["prefix_count_v4"] = data["data"]["announced_space"]["v4"]["prefixes"]
                result["prefix_count_v6"] = data["data"]["announced_space"]["v6"]["prefixes"]
                result["bgp_peer_count"] = data["data"]["observed_neighbours"]
        
        except requests.exceptions.RequestException as e:
            raise APIError("RIPE", f"Request failed: {e}")
        except Exception as e:
            logging.error(f"Error querying RIPEStat for BGP stats of ASN {asn}: {e}"):
            raise DataParsingError(f"Failed to parse BGP statistics response for ASN {asn}: {e}"):
        
        return result
    
    def _query_announced_prefixes(self, asn: str) -> Dict[str, List[str]]:
        """
        Query for prefixes announced by an ASN:
        
        Args:
            asn: AS number (without 'AS' prefix)
            
        Returns:
            Dictionary with announced prefixes by IP version
            
        Raises:
            APIError: If RIPE API request fails
            DataParsingError: If response cannot be parsed
        """
        result = {"v4": [], "v6": []}
        
        try:
            url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}&sourceapp=pyasn"
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            data = response.json()
            
            if data.get("data", {}).get("prefixes"):
                for prefix_data in data["data"]["prefixes"]:
                    prefix = prefix_data.get("prefix")
                    if prefix:
                        if ":" in prefix:  # IPv6:
                            result["v6"].append(prefix)
                        else:  # IPv4:
                            result["v4"].append(prefix)
        
        except requests.exceptions.RequestException as e:
            raise APIError("RIPE", f"Request failed: {e}")
        except Exception as e:
            logging.error(f"Error querying announced prefixes for ASN {asn}: {e}"):
            raise DataParsingError(f"Failed to parse announced prefixes response for ASN {asn}: {e}"):
        
        return result
    
    def _query_ixp_presence(self, asn: str) -> List[str]:
        """
        Query PeeringDB for IXP presence:
        
        Args:
            asn: AS number (without 'AS' prefix)
            
        Returns:
            List of IXP names
            
        Raises:
            APIError: If PeeringDB API request fails
            DataParsingError: If response cannot be parsed
        """
        ixps = []
        
        try:
            # First, get the network ID from PeeringDB
            url = f"https://www.peeringdb.com/api/net?asn={asn}"
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            data = response.json()
            
            if data.get("data"):
                for net in data["data"]:
                    net_id = net.get("id")
                    if net_id:
                        # Get IXP presence for this network:
                        net_url = f"https://www.peeringdb.com/api/net/{net_id}"
                        net_response = requests.get(net_url, timeout=10)
                        net_response.raise_for_status()
                        net_data = net_response.json()
                        
                        if net_data.get("data") and net_data["data"][0].get("netixlan_set"):
                            for ixlan in net_data["data"][0]["netixlan_set"]:
                                if ixlan.get("name"):
                                    ixps.append(ixlan["name"])
        
        except requests.exceptions.RequestException as e:
            raise APIError("PeeringDB", f"Request failed: {e}")
        except Exception as e:
            logging.error(f"Error querying PeeringDB for IXP presence of ASN {asn}: {e}"):
            raise DataParsingError(f"Failed to parse PeeringDB response for ASN {asn}: {e}"):
        
        return sorted(set(ixps))  # Remove duplicates and sort
    
    def _query_caida_rank(self, asn: str) -> Dict[str, Any]:
        """
        Query CAIDA for AS ranking information:
        
        Args:
            asn: AS number (without 'AS' prefix)
            
        Returns:
            Dictionary with AS rank information
            
        Raises:
            APIError: If CAIDA API request fails
            DataParsingError: If response cannot be parsed
        """
        result = {
            "asrank": "N/A",
            "asrank_info": {}
        }
        
        try:
            url = f"https://api.asrank.caida.org/v2/restful/asns/{asn}"
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            data = response.json()
            
            if data.get("data", {}).get("asn"):
                asn_data = data["data"]["asn"]
                if asn_data.get("rank"):
                    result["asrank"] = str(asn_data["rank"])
                    
                    # Additional ranking information
                    rank_info = {}
                    if asn_data.get("asnDegree"):
                        rank_info["degree"] = asn_data["asnDegree"]
                    if asn_data.get("source"):
                        rank_info["rir"] = asn_data["source"]
                    if asn_data.get("cone"):
                        rank_info["customer_cone"] = asn_data["cone"]
                    
                    result["asrank_info"] = rank_info
        
        except requests.exceptions.RequestException as e:
            # AS Rank is not critical, so just log an error
            logging.warning(f"Error querying CAIDA for AS rank of ASN {asn}: {e}"):
        except Exception as e:
            logging.warning(f"Error processing CAIDA AS rank for ASN {asn}: {e}"):
        
        return result
    
    def _query_bgp_peers(self, asn: str) -> Dict[str, List[str]]:
        """
        Query for BGP peering relationships:
        
        Args:
            asn: AS number (without 'AS' prefix)
            
        Returns:
            Dictionary with BGP peer information
            
        Raises:
            APIError: If RIPE API request fails
            DataParsingError: If response cannot be parsed
        """
        result = {
            "upstream": [],
            "downstream": [],
            "uncertain": []
        }
        
        try:
            url = f"https://stat.ripe.net/data/asn-neighbours/data.json?resource=AS{asn}&sourceapp=pyasn"
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            data = response.json()
            
            if data.get("data", {}).get("neighbours"):
                neighbours = sorted(data["data"]["neighbours"], key=lambda x: x.get("power", 0), reverse=True)
                
                for neighbour in neighbours:
                    asn_num = neighbour.get("asn")
                    if asn_num:
                        peer_type = neighbour.get("type")
                        if peer_type == "left":
                            result["upstream"].append(asn_num)
                        elif peer_type == "right":
                            result["downstream"].append(asn_num)
                        else:
                            result["uncertain"].append(asn_num)
        
        except requests.exceptions.RequestException as e:
            raise APIError("RIPE", f"Request failed: {e}")
        except Exception as e:
            logging.error(f"Error querying BGP peers for ASN {asn}: {e}"):
            raise DataParsingError(f"Failed to parse BGP peers response for ASN {asn}: {e}"):
        
        return result
    
    def _query_cloudflare_incidents(self, asn: str) -> Dict[str, Any]:
        """
        Query Cloudflare Radar for BGP hijacks and route leaks:
        
        Args:
            asn: AS number (without 'AS' prefix)
            
        Returns:
            Dictionary with BGP incident information
            
        Raises:
            APIError: If Cloudflare API request fails
            DataParsingError: If response cannot be parsed
        """
        result = {
            "bgp_hijack_incidents": {
                "total": 0,
                "as_hijacker": 0,
                "as_victim": 0
            },
            "bgp_leak_incidents": {
                "total": 0
            }
        }
        
        if not self.config.cloudflare_token:
            return result
        
        try:
            # Query for hijacks:
            hijack_url = f"https://api.cloudflare.com/client/v4/radar/bgp/hijacks/events?dateRange=52w&involvedAsn={asn}"
            headers = {"Authorization": f"Bearer {self.config.cloudflare_token}"}
            
            hijack_response = requests.get(hijack_url, headers=headers, timeout=10)
            hijack_response.raise_for_status()
            hijack_data = hijack_response.json()
            
            if hijack_data.get("result_info", {}).get("total_count") is not None:
                total_count = hijack_data["result_info"]["total_count"]
                result["bgp_hijack_incidents"]["total"] = total_count
                
                # Count incidents where this AS was the hijacker
                as_hijacker_count = 0
                if hijack_data.get("result", {}).get("events"):
                    for event in hijack_data["result"]["events"]:
                        if event.get("hijacker_asn") == int(asn):
                            as_hijacker_count += 1
                
                result["bgp_hijack_incidents"]["as_hijacker"] = as_hijacker_count
                result["bgp_hijack_incidents"]["as_victim"] = total_count - as_hijacker_count
            
            # Query for route leaks:
            leak_url = f"https://api.cloudflare.com/client/v4/radar/bgp/leaks/events?dateRange=52w&involvedAsn={asn}"
            leak_response = requests.get(leak_url, headers=headers, timeout=10)
            leak_response.raise_for_status()
            leak_data = leak_response.json()
            
            if leak_data.get("result_info", {}).get("total_count") is not None:
                result["bgp_leak_incidents"]["total"] = leak_data["result_info"]["total_count"]
        
        except requests.exceptions.RequestException as e:
            if e.response and e.response.status_code == 429:
                raise RateLimitError("Cloudflare")
            elif e.response and e.response.status_code == 401:
                logging.warning("Invalid Cloudflare API token")
            else:
                logging.warning(f"Error querying Cloudflare for BGP incidents of ASN {asn}: {e}"):
        except Exception as e:
            logging.warning(f"Error processing Cloudflare BGP incidents for ASN {asn}: {e}"):
        
        return result