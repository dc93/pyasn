"""
Organization search implementation
"""

import logging
import re
import subprocess
from typing import Dict, List, Optional, Any

from pyasn.core.config import Config
from pyasn.core.exceptions import (
    ValidationError, NetworkError, APIError, DataParsingError,
    LookupError
)
from pyasn.core.models import OrganizationSearchResult
from pyasn.services import OrganizationService
from pyasn.utils.cache import Cache
from pyasn.utils.network import NetworkUtils
from pyasn.utils.validation import Validator

class OrganizationSearchService(OrganizationService):
    """Organization search service implementation"""
    
    def __init__(self, config: Config, network_utils=None, cache=None):
        """
        Initialize organization search service
        
        Args:
            config: Configuration object
            network_utils: NetworkUtils instance (optional)
            cache: Cache instance (optional)
        """
        self.config = config
        self.network_utils = network_utils or NetworkUtils()
        self.cache = cache or Cache(config.cache_dir)
    
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
        Validator.validate_required(org_name, "org_name")
        
        try:
            # Try to get from cache
            cache_key = f"org_search_{org_name}"
            cached_result = self.cache.get(cache_key)
            if cached_result:
                return OrganizationSearchResult(**cached_result)
            
            result = OrganizationSearchResult(
                query=org_name,
                matches=[],
                ipv4_networks=[],
                ipv6_networks=[]
            )
            
            # Use whois for organization search
            try:
                whois_cmd = ["whois", "-h", "whois.pwhois.org", f"registry org-name={org_name}"]
                output = subprocess.check_output(whois_cmd, universal_newlines=True)
                
                # Extract organizations
                org_matches = []
                for line in output.splitlines():
                    if line.startswith("Org-Name:"):
                        org_name = line.replace("Org-Name:", "").strip()
                        if org_name not in org_matches:
                            org_matches.append(org_name)
                
                result.matches = org_matches
                
                # If we have matches, get network ranges for the first one
                if org_matches:
                    ipv4_networks = self._get_networks_for_org(org_matches[0], "4")
                    ipv6_networks = self._get_networks_for_org(org_matches[0], "6")
                    
                    result.ipv4_networks = ipv4_networks
                    result.ipv6_networks = ipv6_networks
            
            except subprocess.SubprocessError as e:
                logging.warning(f"Error executing whois command for org search: {e}")
                raise LookupError(f"Organization search failed: {e}")
            
            # Cache the result
            self.cache.set(cache_key, result.__dict__)
            
            return result
        
        except LookupError:
            raise
        except Exception as e:
            logging.error(f"Unexpected error in organization search for {org_name}: {e}")
            raise LookupError(f"Organization search failed: {e}")
    
    def _get_networks_for_org(self, org_name: str, ip_version: str) -> List[Dict[str, str]]:
        """
        Get network ranges for an organization
        
        Args:
            org_name: Organization name
            ip_version: IP version (4 or 6)
            
        Returns:
            List of network information dictionaries
        """
        networks = []
        
        try:
            # Get the organization ID
            whois_cmd = ["whois", "-h", "whois.pwhois.org", f"registry org-name={org_name}"]
            output = subprocess.check_output(whois_cmd, universal_newlines=True)
            
            org_ids = []
            for line in output.splitlines():
                if line.startswith("Org-ID:"):
                    org_id = line.replace("Org-ID:", "").strip()
                    if org_id not in org_ids:
                        org_ids.append(org_id)
            
            # For each Org-ID, get network blocks
            for org_id in org_ids:
                if ip_version == "4":
                    cmd = ["whois", "-h", "whois.pwhois.org", f"netblock org-id={org_id}"]
                else:
                    cmd = ["whois", "-h", "whois.pwhois.org", f"netblock6 org-id={org_id}"]
                
                try:
                    net_output = subprocess.check_output(cmd, universal_newlines=True)
                    
                    # Parse network data
                    current_net = {}
                    for line in net_output.splitlines():
                        if line.startswith("*>"):
                            # New network entry
                            if current_net:
                                networks.append(current_net)
                                current_net = {}
                            
                            parts = line.replace("*>", "").strip().split("|")
                            if len(parts) >= 4:
                                prefix = parts[0].strip()
                                net_name = parts[1].strip()
                                net_type = parts[2].strip()
                                reg_date = parts[3].strip()
                                
                                current_net = {
                                    "prefix": prefix,
                                    "net_name": net_name,
                                    "net_type": net_type if net_type != "unknown" else "",
                                    "registration_date": reg_date
                                }
                    
                    # Add the last network
                    if current_net:
                        networks.append(current_net)
                
                except subprocess.SubprocessError as e:
                    logging.warning(f"Error getting networks for org_id {org_id}: {e}")
        
        except subprocess.SubprocessError as e:
            logging.warning(f"Error getting organization IDs for {org_name}: {e}")
        except Exception as e:
            logging.warning(f"Error getting networks for organization {org_name}: {e}")
        
        return networks