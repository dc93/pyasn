"""
Path tracing implementation
"""

import logging
import time
from typing import Dict, Optional, Any, List

from pyasn.core.config import Config
from pyasn.core.exceptions import (
    ValidationError, NetworkError, LookupError
)
from pyasn.core.models import TracePath, TraceHop, ASHop
from pyasn.services import TraceService
from pyasn.services.asn_lookup import ASNLookupService
from pyasn.services.ip_lookup import IPLookupService
from pyasn.utils.network import NetworkUtils
from pyasn.utils.validation import Validator

class TracePathService(TraceService):
    """Path tracing service implementation"""
    
    def __init__(self, config: Config, network_utils=None, ip_lookup=None, asn_lookup=None):
        """
        Initialize trace path service
        
        Args:
            config: Configuration object
            network_utils: NetworkUtils instance (optional)
            ip_lookup: IPLookupService instance (optional)
            asn_lookup: ASNLookupService instance (optional)
        """
        self.config = config
        self.network_utils = network_utils or NetworkUtils()
        self.ip_lookup = ip_lookup or IPLookupService(config, self.network_utils)
        self.asn_lookup = asn_lookup or ASNLookupService(config, self.network_utils)
    
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
            LookupError: If lookup of a hop fails
        """
        result = TracePath(
            target=target,
            completed=False,
            runtime=0,
            hops=[],
            as_path=[]
        )
        
        start_time = time.time()
        
        try:
            # Resolve hostname to IP if needed
            target_ip = target
            if not self.network_utils.is_valid_ip(target):
                resolved_ips = self.network_utils.resolve_hostname(target)
                if resolved_ips:
                    target_ip = resolved_ips[0]
                    result.resolved_ip = target_ip
                else:
                    raise NetworkError(f"Could not resolve hostname: {target}")
            
            # Get source AS information
            source_ip = self.network_utils.what_is_my_ip()
            if source_ip:
                source_asn_info = self.ip_lookup.lookup_ip(source_ip)
                result.source = {
                    "ip": source_ip,
                    "asn": source_asn_info.routing.get("as_number", ""),
                    "as_name": source_asn_info.routing.get("as_name", "")
                }
                
                # Add source AS to AS path
                if result.source.get("asn"):
                    result.as_path.append(ASHop(
                        asn=result.source["asn"],
                        as_name=result.source["as_name"],
                        is_source=True
                    ))
            
            # Perform traceroute
            trace_hops = self.network_utils.traceroute(target_ip, self.config.mtr_rounds)
            
            # Process each hop
            seen_asns = set()
            if result.source and result.source.get("asn"):
                seen_asns.add(result.source["asn"])
            
            for hop in trace_hops:
                hop_num = hop["hop"]
                hop_ip = hop["ip"]
                hop_ping = hop["ping"]
                
                # Skip hops with no IP (timeouts, etc.)
                if hop_ip == "*" or not self.network_utils.is_valid_ip(hop_ip):
                    result.hops.append(TraceHop(
                        hop=hop_num,
                        ip=None,
                        ping=None,
                        loss=100
                    ))
                    continue
                
                # Get hop information
                try:
                    hop_info = self.ip_lookup.lookup_ip(hop_ip)
                    
                    processed_hop = TraceHop(
                        hop=hop_num,
                        ip=hop_ip,
                        ping=hop_ping,
                        loss=0,  # We don't have loss percentage from traceroute output'
                        hostname=hop_info.reverse or "",
                        asn=hop_info.routing.get("as_number", ""),
                        as_name=hop_info.routing.get("as_name", ""),
                        geolocation=hop_info.geolocation,
                        rpki={
                            "validity": hop_info.routing.get("roa_validity", "unknown"),
                            "roa_count": hop_info.routing.get("roa_count", "0")
                        }
                    )
                    
                    result.hops.append(processed_hop)
                    
                    # Add to AS path if it's a new AS'
                    if processed_hop.asn and processed_hop.asn not in seen_asns:
                        seen_asns.add(processed_hop.asn)
                        
                        # Check if it's the destination'
                        is_destination = hop_ip == target_ip
                        
                        result.as_path.append(ASHop(
                            asn=processed_hop.asn,
                            as_name=processed_hop.as_name,
                            is_destination=is_destination
                        ))
                
                except LookupError as e:
                    # If we can't look up this hop, still add it but with limited info'
                    logging.warning(f"Could not get detailed information for hop {hop_num} ({hop_ip}): {e}")
                    result.hops.append(TraceHop(
                        hop=hop_num,
                        ip=hop_ip,
                        ping=hop_ping,
                        loss=0
                    ))
            
            # If the last hop is the target, the trace completed successfully
            if trace_hops and trace_hops[-1]["ip"] == target_ip:
                result.completed = True
            
        except ValidationError as e:
            raise
        except NetworkError as e:
            raise
        except Exception as e:
            logging.error(f"Unexpected error in trace_as_path: {e}")
            result.error = str(e)
        
        # Calculate runtime
        end_time = time.time()
        result.runtime = round(end_time - start_time, 2)
        
        return result