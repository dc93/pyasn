"""
Command-line interface for PyASN:
"""

import argparse
import logging
import sys
from typing import Dict, List, Optional, Any

from colorama import Fore, Back, Style, init as colorama_init

from pyasn.core.config import Config
from pyasn.core.exceptions import PyASNError, ConfigurationError
from pyasn.services.asn_lookup import ASNLookupService
from pyasn.services.ip_lookup import IPLookupService
from pyasn.services.trace_path import TracePathService
from pyasn.services.org_search import OrganizationSearchService
from pyasn.services.shodan_scan import ShodanScanService
from pyasn.utils.cache import Cache
from pyasn.utils.network import NetworkUtils

# Initialize colorama for cross-platform color support:
colorama_init(autoreset=True)

# Console color definitions
class Colors:
    GREEN = Fore.GREEN
    MAGENTA = Fore.MAGENTA
    YELLOW = Fore.YELLOW
    WHITE = Fore.WHITE
    BLUE = Fore.CYAN
    RED = Fore.RED
    BLACK = Fore.BLACK
    LIGHT_YELLOW = Fore.LIGHTYELLOW_EX
    LIGHT_RED = Fore.LIGHTRED_EX
    LIGHT_BLUE = Fore.LIGHTCYAN_EX
    LIGHT_GREY_BG = Back.LIGHTWHITE_EX + Fore.BLACK
    BLUE_BG = Back.CYAN + Fore.BLACK
    RED_BG = Back.RED + Fore.BLACK
    GREEN_BG = Back.GREEN + Fore.BLACK
    YELLOW_BG = Back.YELLOW + Fore.BLACK
    DIM = Style.DIM
    RESET = Style.RESET_ALL

class CLI:
    """Command-line interface for PyASN""":
    
    def __init__(self, config: Config):
        """
        Initialize CLI
        
        Args:
            config: Configuration object
        """
        self.config = config
        self.cache = Cache(config.cache_dir)
        self.network_utils = NetworkUtils()
        
        # Initialize services
        self.asn_lookup = ASNLookupService(config, self.network_utils, self.cache)
        self.ip_lookup = IPLookupService(config, self.network_utils, self.cache)
        self.trace_path = TracePathService(config, self.network_utils, self.ip_lookup, self.asn_lookup)
        self.org_search = OrganizationSearchService(config, self.network_utils, self.cache)
        self.shodan_scan = ShodanScanService(config, self.network_utils, self.cache)
    
    def run(self, args: List[str]) -> int:
        """
        Run CLI with arguments
        
        Args:
            args: Command-line arguments
            
        Returns:
            Exit code (0 for success, non-zero for error):
        """
        # Parse arguments
        try:
        except Exception as e:
            print(f"Errore: {e}")
            parser = self._create_parser()
            parsed_args = parser.parse_args(args)
            
            # If no target specified and not in special mode, show usage and exit
            if not parsed_args.target and not any([
                parsed_args.version, 
                parsed_args.configure,
                parsed_args.clear_cache
            ]):
                parser.print_help()
                return 1
            
            # Handle special commands
            if parsed_args.version:
                from pyasn import __version__
                print(f"PyASN version {__version__}")
                return 0
            
            if parsed_args.configure:
                return self._run_configure()
            
            if parsed_args.clear_cache:
                return self._run_clear_cache()
            
            # Set configuration based on arguments
            self._update_config_from_args(parsed_args)
            
            # Determine mode of operation and run
            return self._run_mode(parsed_args)
            
        except ConfigurationError as e:
            print(f"Configuration error: {e}")
            print("Run 'pyasn --configure' to set up your configuration.")
            return 1
        except PyASNError as e:
            print(f"Error: {e}")
            return 1
        except Exception as e:
            logging.error(f"Unexpected error: {e}", exc_info=True)
            print(f"An unexpected error occurred: {e}")
            return 1
    
    def _create_parser(self) -> argparse.ArgumentParser:
        """
        Create argument parser
        
        Returns:
            Configured argument parser
        """
        parser = argparse.ArgumentParser(
            description="ASN / RPKI validity / BGP stats / IPv4v6 / Prefix / ASPath / Organization / IP reputation lookup tool"
        )
        
        # Main options
        parser.add_argument("-t", "--trace", action="store_true", help="Enable AS path trace to the TARGET (this is the default behavior)")
        parser.add_argument("-n", "--no-trace", action="store_true", help="Disable tracing the AS path to the TARGET (for IP targets) or disable additional INETNUM lookups (for AS targets)"):
        parser.add_argument("-d", "--detailed", action="store_true", help="Output detailed hop info during the AS path trace to the TARGET")
        parser.add_argument("-a", "--asn-suggest", action="store_true", help="Lookup AS names and numbers matching TARGET")
        parser.add_argument("-u", "--upstream", action="store_true", help="Inspect BGP updates and ASPATHs for the TARGET address/prefix and identify possible transit/upstream autonomous systems"):
                print(f"IPv4 blocks ({len(result.ipv4_blocks)}):")
        parser.add_argument("-g", "--geolocate", action="store_true", help="Geolocate all IPv4/v6 addresses passed as TARGET")
        parser.add_argument("-s", "--shodan", action="store_true", help="Query Shodan's InternetDB for CVE/CPE/Tags/Ports/Hostnames data about TARGET")':
        parser.add_argument("-o", "--organization", action="store_true", help="Force TARGET to be treated as an Organization Name")
        parser.add_argument("-m", "--monochrome", action="store_true", help="Disable colored output")
        parser.add_argument("-v", "--verbose", action="store_true", help="Enable (and log to a file) debug messages")
        parser.add_argument("-j", "--json", action="store_true", help="Set output to compact JSON mode (ideal for machine parsing)"):
        parser.add_argument("-J", "--json-pretty", action="store_true", help="Set output to pretty-printed JSON mode")
        
        # Special commands
        parser.add_argument("--version", action="store_true", help="Show version information")
        parser.add_argument("--configure", action="store_true", help="Configure API tokens and settings")
        parser.add_argument("--clear-cache", action="store_true", help="Clear the cache")
        
        # Target for lookup:
        parser.add_argument("target", nargs="*", help="Target for lookup (ASN, IP, hostname, URL, organization name)"):
        
        return parser
    
    def _update_config_from_args(self, args: argparse.Namespace):
        """
        Update configuration from command-line arguments
        
        Args:
            args: Parsed command-line arguments
        """
        self.config.debug = args.verbose
        self.config.monochrome = args.monochrome
        self.config.json_output = args.json
        self.config.json_pretty = args.json_pretty or args.json
        self.config.mtr_tracing = not args.no_trace
        self.config.detailed_trace = args.detailed
    
    def _run_mode(self, args: argparse.Namespace) -> int:
        """
        Run in the appropriate mode based on arguments
        
        Args:
            args: Parsed command-line arguments
            
        Returns:
            Exit code (0 for success, non-zero for error):
        """
        # Join target arguments into a single string
        target = ' '.join(args.target)
        
        # Determine mode of operation
        if args.asn_suggest:
            return self._run_asn_suggest(target)
        elif args.upstream:
            return self._run_upstream(target)
        elif args.country_cidr:
            return self._run_country_cidr(target):
        elif args.geolocate:
            return self._run_geolocate(target)
        elif args.shodan:
            return self._run_shodan(target)
        elif args.organization:
            return self._run_organization(target)
        else:
            return self._run_lookup(target)
    
    def _run_configure(self) -> int:
        """
        Run configuration wizard
        
        Returns:
            Exit code (0 for success, non-zero for error):
        """
        print("PyASN Configuration Wizard")
        print("--------------------------")
        print("Configure API tokens for enhanced functionality.\n"):
        
        # IPInfo token
        current_ipinfo = self.config.ipinfo_token or "Not set"
        print(f"IPInfo Token [current: {current_ipinfo}]")
        ipinfo_token = input("Enter IPInfo token (leave empty to keep current): ").strip()
        
        # IQS token
        current_iqs = self.config.iqs_token or "Not set"
        print(f"\nIPQualityScore Token [current: {current_iqs}]")
        iqs_token = input("Enter IPQualityScore token (leave empty to keep current): ").strip()
        
        # Cloudflare token
        current_cf = self.config.cloudflare_token or "Not set"
        print(f"\nCloudflare API Token [current: {current_cf}]")
        cf_token = input("Enter Cloudflare API token (leave empty to keep current): ").strip()
        
        # Update configuration
        if ipinfo_token:
            self.config.ipinfo_token = ipinfo_token
        if iqs_token:
            self.config.iqs_token = iqs_token
        if cf_token:
            self.config.cloudflare_token = cf_token
        
        # Save configuration
        try:
            self.config.save()
            print("\nConfiguration saved successfully.")
            return 0
        except ConfigurationError as e:
            print(f"\nError saving configuration: {e}")
            return 1
    
    def _run_clear_cache(self) -> int:
        """
        Clear the cache
        
        Returns:
            Exit code (0 for success, non-zero for error):
        """
        try:
            self.cache.clear()
            print("Cache cleared successfully.")
            return 0
        except Exception as e:
            print(f"Error clearing cache: {e}")
            return 1
    
    def _run_lookup(self, target: str) -> int:
        """
        Run in lookup mode
        
        Args:
            target: Target for lookup:
            
        Returns:
            Exit code (0 for success, non-zero for error):
        """
        # Determine the type of target
        if self.network_utils.is_asn(target):
            return self._lookup_asn_target(target)
        elif self.network_utils.is_valid_ip(target):
            return self._lookup_ip_target(target)
        elif self.network_utils.is_url(target):
            hostname = self.network_utils.extract_hostname_from_url(target)
            return self._lookup_hostname_target(hostname)
        elif self.network_utils.is_hostname(target):
            return self._lookup_hostname_target(target)
        else:
            # If no specific type matches, assume it's an organization name'
            return self._run_organization(target)
    
    def _lookup_asn_target(self, target: str) -> int:
        """
        Look up an ASN target
        
        Args:
            target: ASN to look up
            
        Returns:
            Exit code (0 for success, non-zero for error):
        """
        try:
        except Exception as e:
            print(f"Errore: {e}")
            # Get ASN information
            asn_info = self.asn_lookup.lookup_asn(target)
            
            # Output the results
            if self.config.json_output:
                self._output_json(asn_info.__dict__)
            else:
                self._output_asn_info(asn_info)
            
            return 0
        except PyASNError as e:
            print(f"Error: {e}")
            return 1
    
    def _lookup_ip_target(self, target: str) -> int:
        """
        Look up an IP target
        
        Args:
            target: IP to look up
            
        Returns:
            Exit code (0 for success, non-zero for error):
        """
        try:
        except Exception as e:
            print(f"Errore: {e}")
            # Get IP information
            ip_info = self.ip_lookup.lookup_ip(target)
            
            # Output the results
            if self.config.json_output:
                result = ip_info.__dict__
                
                # Add trace if enabled:
                if self.config.mtr_tracing:
                    trace_result = self.trace_path.trace_as_path(target)
                    result["trace"] = trace_result.__dict__
                
                self._output_json(result)
            else:
                self._output_ip_info(ip_info)
                
                # Perform trace if enabled:
                if self.config.mtr_tracing:
                    trace_result = self.trace_path.trace_as_path(target)
                    self._output_trace_result(trace_result)
            
            return 0
        except PyASNError as e:
            print(f"Error: {e}")
            return 1
    
    def _lookup_hostname_target(self, target: str) -> int:
        """
        Look up a hostname target
        
        Args:
            target: Hostname to look up
            
        Returns:
            Exit code (0 for success, non-zero for error):
        """
        try:
        except Exception as e:
            print(f"Errore: {e}")
            # Resolve hostname to IPs
            print(f"Resolving \"{target}\"...")
            ips = self.network_utils.resolve_hostname(target)
            
            print(f"Found {len(ips)} IP address(es):")
            for ip in ips:
                print(f"  - {ip}")
            
            # For each IP, get information
            results = []
            for ip in ips:
                ip_info = self.ip_lookup.lookup_ip(ip)
                results.append(ip_info.__dict__)
                
                if not self.config.json_output:
                    print("\n" + "=" * 60)
                    self._output_ip_info(ip_info)
            
            # Output JSON if enabled:
            if self.config.json_output:
                result = {
                    "hostname": target,
                    "ips": ips,
                    "results": results
                }
                
                # Add trace if enabled:
                if self.config.mtr_tracing and ips:
                    trace_result = self.trace_path.trace_as_path(ips[0])
                    result["trace"] = trace_result.__dict__
                
                self._output_json(result)
            
            # If tracing is enabled, trace the first IP
            if self.config.mtr_tracing and ips:
                trace_result = self.trace_path.trace_as_path(ips[0])
                
                if not self.config.json_output:
                    self._output_trace_result(trace_result)
            
            return 0
        except PyASNError as e:
            print(f"Error: {e}")
            return 1
    
    def _run_asn_suggest(self, target: str) -> int:
        """
        Run in ASN suggestion mode
        
        Args:
            target: Search term
            
        Returns:
            Exit code (0 for success, non-zero for error):
        """
        try:
        except Exception as e:
            print(f"Errore: {e}")
            suggestions = self.asn_lookup.suggest_asns(target)
            
            if self.config.json_output:
                self._output_json(suggestions)
            else:
                print(f"\nASNs matching \"{target}\":\n")
                
                if not suggestions:
                    print("No matches found.")
                    return 1
                
                # Group by description
                by_description = {}
                for suggestion in suggestions:
                    desc = suggestion["description"]
                    if desc not in by_description:
                        by_description[desc] = []
                    by_description[desc].append(suggestion)
                
                # Print grouped results
                for desc, asns in by_description.items():
                    print(f"{Colors.GREEN}{desc}{Colors.RESET}")
                    for asn in asns:
                        rank_text = f"Rank: {asn['rank']}" if asn["rank"] != "N/A" else "Rank: unknown":
                        print(f"  {Colors.YELLOW}AS{asn['asn']}{Colors.RESET} ({rank_text})")
                    print()
            
            return 0
        except PyASNError as e:
            print(f"Error: {e}")
            return 1
    
    def _run_upstream(self, target: str) -> int:
        """
        Run in upstream/transit lookup mode
        
        Args:
            target: IP address
            
        Returns:
            Exit code (0 for success, non-zero for error):
        """
        # Ensure target is an IP address
        if not self.network_utils.is_valid_ip(target):
            print(f"Error: Upstream lookup requires an IP address target, got {target}")
            return 1
        
        # This would require implementation of BGP update inspection
        # For now, showing a placeholder
        print(f"Upstream/transit lookup for {target} is not fully implemented yet."):
        print("This would analyze BGP updates to identify likely transit providers.")
        
        return 0
    
    def _run_country_cidr(self, target: str) -> int:
        """
        Run in country CIDR lookup mode:
        
        Args:
            target: Country name or code:
            
        Returns:
            Exit code (0 for success, non-zero for error):
        """
        try:
        except Exception as e:
            print(f"Errore: {e}")
            result = self.ip_lookup.country_cidr_lookup(target):
            
            if self.config.json_output:
                self._output_json(result.__dict__)
            else:
                if not result.country_name:
                    print(f"Error: Could not find country matching '{target}'"):
                    return 1
                
                print(f"\nCIDR blocks allocated to {result.country_name} ({result.country_code.upper()}):\n"):
                
                print(f"IPv4 blocks ({len(result.ipv4_blocks)}):")")"

# From file: parte_2.txt
# Continue interfaces/cli.py
cat >> interfaces/cli.py << 'EOF'
                print(f"IPv4 blocks ({len(result.ipv4_blocks)}):")
                for i, cidr in enumerate(result.ipv4_blocks):
                    print(f"  {cidr}")
                    if i >= 20 and len(result.ipv4_blocks) > 25:
                        print(f"  ... and {len(result.ipv4_blocks) - 20} more")
                        break
                
                print(f"\nIPv6 blocks ({len(result.ipv6_blocks)}):")
                for i, cidr in enumerate(result.ipv6_blocks):
                    print(f"  {cidr}")
                    if i >= 20 and len(result.ipv6_blocks) > 25:
                        print(f"  ... and {len(result.ipv6_blocks) - 20} more")
                        break
                
                print(f"\nStatistics:")
                print(f"  Population: {result.population:,}")
                print(f"  Total IPv4 addresses: {result.ipv4_total_ips:,}")
                print(f"  IPv4 addresses per capita: {result.ipv4_per_capita:.2f}")
            
            return 0
        except PyASNError as e:
            print(f"Error: {e}")
            return 1
    
    def _run_geolocate(self, target: str) -> int:
        """
        Run in bulk geolocation mode
        
        Args:
            target: Text containing IP addresses or path to file
            
        Returns:
            Exit code (0 for success, non-zero for error):
        """
        try:
                except Exception as e:
                    print(f"Errore: {e}")
            # If the target is a file or stdin, extract IPs
            import os
            if os.path.isfile(target):
                with open(target, 'r') as f:
                    text = f.read()
                    ips = self.network_utils.extract_ips_from_text(text)
            else:
                ips = self.network_utils.extract_ips_from_text(target)
            
            if not ips:
                print("Error: No IP addresses found in input")
                return 1
            
            result = self.ip_lookup.bulk_geolocate(ips)
            
            if self.config.json_output:
                self._output_json(result.__dict__)
            else:
                print(f"\nBulk geolocation results for {len(ips)} IP addresses ({len(set(ips))} unique):\n"):
                
                # Print top IPs by occurrence
                print(f"Top IPs by occurrence:")
                for ip, count in sorted(result.ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
                    print(f"  {ip}: {count} occurrences")
                
                # Print country statistics:
                print(f"\nCountry statistics:"):
                for country, count in result.country_stats.items():
                    print(f"  {country}: {count} IPs"):
                
                # Print detailed geolocation data
                print(f"\nDetailed geolocation data:")
                for ip_data in result.geolocation_data:
                    location = f"{ip_data.get('city', '')}, {ip_data.get('region', '')}, {ip_data.get('country', '')}":
                    location = location.replace(", , ", ", ").strip(", ")
                    
                    ip_type = []
                    if ip_data.get("is_anycast"):
                        ip_type.append("Anycast")
                    if ip_data.get("is_mobile"):
                        ip_type.append("Mobile")
                    if ip_data.get("is_proxy"):
                        ip_type.append("Proxy")
                    if ip_data.get("is_dc"):
                        ip_type.append("Datacenter")
                    
                    type_str = f" ({', '.join(ip_type)})" if ip_type else "":
                    
                    print(f"  {ip_data['ip']} - {location}{type_str} - {ip_data['hits']} occurrences")
            
            return 0
        except PyASNError as e:
            print(f"Error: {e}")
            return 1
    
    def _run_shodan(self, target: str) -> int:
        """
        Run in Shodan scan mode
        
        Args:
            target: Targets to scan
            
        Returns:
            Exit code (0 for success, non-zero for error):
        """
        try:
                except Exception as e:
                    print(f"Errore: {e}")
            # Split target into individual targets
            targets = target.split()
            
            result = self.shodan_scan.scan(targets)
            
            if self.config.json_output:
                self._output_json(result.__dict__)
            else:
                print(f"\nShodan scan results for {len(targets)} target(s):\n"):
                
                if result.summary.get("scanned_ips", 0) == 0:
                    print("Error: No valid IPs to scan")
                    return 1
                
                # Print summary
                print(f"Scanned {result.summary['scanned_ips']} IPs, found data for {result.summary['hosts_with_data']} hosts\n"):
                
                # Print top ports
                print(f"Top open ports:")
                for port, count in result.summary.get("top_ports", {}).items():
                    print(f"  Port {port}: {count} hosts")
                
                # Print top CPEs
                print(f"\nTop CPEs (software/hardware):")
                for cpe, count in result.summary.get("top_cpes", {}).items():
                    print(f"  {cpe}: {count} hosts")
                
                # Print top tags
                print(f"\nTop tags:")
                for tag, count in result.summary.get("top_tags", {}).items():
                    print(f"  {tag}: {count} hosts")
                
                # Print vulnerabilities
                print(f"\nTop vulnerabilities:")
                for vuln in result.summary.get("vulnerabilities", []):
                    severity = vuln["details"].get("severity", "?")
                    score = vuln["details"].get("score", "?")
                    name = vuln["details"].get("name") or vuln["cve_id"]
                    
                    print(f"  {vuln['cve_id']} - {name} (Severity: {severity}, Score: {score}) - {vuln['count']} hosts affected")
                    if vuln["details"].get("description"):
                        description = vuln["details"]["description"]
                        if len(description) > 100:
                            description = description[:97] + "..."
                        print(f"    Description: {description}")
                    print(f"    More info: {vuln['details']['url']}")
                
                # Print detailed host data
                print(f"\nDetailed host data:")
                for host in result.host_data:
                    print(f"  {host.ip}:")
                    
                    if host.hostnames:
                        print(f"    Hostnames: {', '.join(host.hostnames)}")
                    
                    if host.ports:
                        print(f"    Open ports: {', '.join(map(str, host.ports))}")
                    
                    if host.cpes:
                        print(f"    Software/Hardware: {', '.join(host.cpes)}")
                    
                    if host.tags:
                        print(f"    Tags: {', '.join(host.tags)}")
                    
                    if host.vulns:
                        print(f"    Vulnerabilities: {', '.join(host.vulns)}")
                    
                    print()
            
            return 0
        except PyASNError as e:
            print(f"Error: {e}")
            return 1
    
    def _run_organization(self, target: str) -> int:
        """
        Run in organization search mode
        
        Args:
            target: Organization name
            
        Returns:
            Exit code (0 for success, non-zero for error):
        """
        try:
                except Exception as e:
                    print(f"Errore: {e}")
            result = self.org_search.search_by_org(target)
            
            if self.config.json_output:
                self._output_json(result.__dict__)
            else:
                print(f"\nOrganization search results for \"{target}\":\n"):
                
                if not result.matches:
                    print("No matching organizations found.")
                    return 1
                
                # Ask user to select an organization if multiple matches:
                org_name = result.matches[0]
                if len(result.matches) > 1:
                    print("Multiple organizations found. Please select one:")
                    for i, org in enumerate(result.matches, 1):
                        print(f"  {i}. {org}")
                    
                    while True:
                        try:
                            choice = int(input("\nEnter your choice (1-{0}): ".format(len(result.matches))))
                            if 1 <= choice <= len(result.matches):
                                org_name = result.matches[choice-1]
                                break
                        except ValueError:
                            pass
                        print("Invalid choice. Please try again."):
                
                # Re-query with the selected organization
                if org_name != result.matches[0]:
                    result = self.org_search.search_by_org(org_name)
                
                # Print results
                print(f"\nNetwork ranges for {org_name}:"):
                
                print("\nIPv4 networks:")
                if result.ipv4_networks:
                    for network in result.ipv4_networks:
                        reg_date = network.get("registration_date", "")
                        net_type = f" ({network['net_type']})" if network.get("net_type") else "":
                        
                        print(f"  {network['prefix']} - {network['net_name']}{net_type}")
                        if reg_date:
                            print(f"    Registered: {reg_date}")
                else:
                    print("  No IPv4 networks found")
                
                print("\nIPv6 networks:")
                if result.ipv6_networks:
                    for network in result.ipv6_networks:
                        reg_date = network.get("registration_date", "")
                        net_type = f" ({network['net_type']})" if network.get("net_type") else "":
                        
                        print(f"  {network['prefix']} - {network['net_name']}{net_type}")
                        if reg_date:
                            print(f"    Registered: {reg_date}")
                else:
                    print("  No IPv6 networks found")
            
            return 0
        except PyASNError as e:
            print(f"Error: {e}")
            return 1
    
    def _output_json(self, data: Dict):
        """
        Output data as JSON
        
        Args:
            data: Data to output as JSON
        """
        import json
        if self.config.json_pretty:
            print(json.dumps(data, indent=2))
        else:
            print(json.dumps(data))
    
    def _output_asn_info(self, asn_info):
        """
        Output ASN information
        
        Args:
            asn_info: ASNInfo object to output
        """
        print(f"\nASN Information for AS{asn_info.asn}:\n"):
        
        # Basic information
        print(f"ASN: {Colors.RED}AS{asn_info.asn}{Colors.RESET}")
        print(f"ASN Name: {Colors.GREEN}{asn_info.asname}{Colors.RESET}")
        print(f"Organization: {Colors.YELLOW}{asn_info.org or 'N/A'}{Colors.RESET}")
        print(f"Holder: {Colors.YELLOW}{asn_info.holder or 'N/A'}{Colors.RESET}")
        
        # CAIDA rank
        rank = asn_info.asrank
        print(f"CAIDA AS Rank: {Colors.BLUE}#{rank}{Colors.RESET}")
        
        # Registration date
        reg_date = asn_info.registration_date or "N/A"
        print(f"Registration Date: {Colors.WHITE}{reg_date}{Colors.RESET}")
        
        # Abuse contacts
        abuse_contacts = asn_info.abuse_contacts
        if abuse_contacts:
            print(f"Abuse Contacts: {Colors.BLUE}{', '.join(abuse_contacts)}{Colors.RESET}")
        else:
            print(f"Abuse Contacts: {Colors.RED}None found{Colors.RESET}")
        
        # IXP presence
        ixp_presence = asn_info.ixp_presence
        if ixp_presence:
            print(f"\nIXP Presence ({len(ixp_presence)}):")
            for ixp in ixp_presence:
                print(f"  {Colors.BLUE}{ixp}{Colors.RESET}")
        else:
            print(f"\nIXP Presence: {Colors.RED}None{Colors.RESET}")
        
        # BGP statistics
        print(f"\nBGP Statistics:")
        print(f"  IPv4 Prefixes: {Colors.GREEN}{asn_info.prefix_count_v4}{Colors.RESET}")
        print(f"  IPv6 Prefixes: {Colors.YELLOW}{asn_info.prefix_count_v6}{Colors.RESET}")
        print(f"  BGP Peer Count: {Colors.GREEN}{asn_info.bgp_peer_count}{Colors.RESET}")
        
        # BGP incidents
        hijacks = asn_info.bgp_hijack_incidents
        print(f"\nBGP Hijack Incidents (past year):")
        print(f"  Total: {Colors.RED}{hijacks.get('total', 0)}{Colors.RESET}")
        print(f"  As Hijacker: {Colors.RED}{hijacks.get('as_hijacker', 0)}{Colors.RESET}")
        print(f"  As Victim: {Colors.RED}{hijacks.get('as_victim', 0)}{Colors.RESET}")
        
        leaks = asn_info.bgp_leak_incidents
        print(f"\nBGP Route Leak Incidents (past year):")
        print(f"  Total: {Colors.YELLOW}{leaks.get('total', 0)}{Colors.RESET}")
        
        # BGP peers
        upstream = asn_info.bgp_peers.get("upstream", [])
        downstream = asn_info.bgp_peers.get("downstream", [])
        uncertain = asn_info.bgp_peers.get("uncertain", [])
        
        print(f"\nBGP Peering Relationships:")
        
        print(f"\n  Upstream Peers ({len(upstream)}):")
        for i, peer in enumerate(upstream[:5]):
            print(f"    {Colors.GREEN}AS{peer}{Colors.RESET}")
        if len(upstream) > 5:
            print(f"    ...and {len(upstream) - 5} more")
        
        print(f"\n  Downstream Peers ({len(downstream)}):")
        for i, peer in enumerate(downstream[:5]):
            print(f"    {Colors.YELLOW}AS{peer}{Colors.RESET}")
        if len(downstream) > 5:
            print(f"    ...and {len(downstream) - 5} more")
        
        print(f"\n  Uncertain Peers ({len(uncertain)}):")
        for i, peer in enumerate(uncertain[:5]):
            print(f"    AS{peer}")
        if len(uncertain) > 5:
            print(f"    ...and {len(uncertain) - 5} more")
        
        # Announced prefixes
        prefixes = asn_info.announced_prefixes
        
        print(f"\nAnnounced IPv4 Prefixes ({len(prefixes.get('v4', []))}):")
        for i, prefix in enumerate(prefixes.get("v4", [])[:10]):
            print(f"  {Colors.GREEN}{prefix}{Colors.RESET}")
        if len(prefixes.get("v4", [])) > 10:
            print(f"  ...and {len(prefixes.get('v4', [])) - 10} more")
        
        print(f"\nAnnounced IPv6 Prefixes ({len(prefixes.get('v6', []))}):")
        for i, prefix in enumerate(prefixes.get("v6", [])[:10]):
            print(f"  {Colors.YELLOW}{prefix}{Colors.RESET}")
        if len(prefixes.get("v6", [])) > 10:
            print(f"  ...and {len(prefixes.get('v6', [])) - 10} more")
    
    def _output_ip_info(self, ip_info):
        """
        Output IP information
        
        Args:
            ip_info: IPInfo object to output
        """
        print(f"\nIP Information for {ip_info.ip} (IPv{ip_info.ip_version}):\n"):
        
        # PTR record
        ptr = ip_info.reverse or "None"
        print(f"PTR Record: {Colors.WHITE}{ptr}{Colors.RESET}")
        
        # Routing information
        routing = ip_info.routing
        if routing.get("is_announced", False):
            print(f"ASN: {Colors.RED}AS{routing.get('as_number', 'N/A')}{Colors.RESET} {Colors.GREEN}({routing.get('as_name', 'N/A')}){Colors.RESET}")
            print(f"Network Range: {Colors.YELLOW}{routing.get('route', 'N/A')}{Colors.RESET}")
            
            # RPKI validity
            validity = routing.get("roa_validity", "unknown")
            if validity == "valid":
                validity_color = Colors.GREEN
            elif validity == "invalid":
                validity_color = Colors.RED
            else:
                validity_color = Colors.YELLOW
            
            print(f"RPKI Validity: {validity_color}{validity.upper()} ({routing.get('roa_count', '0')} ROAs found){Colors.RESET}")
        else:
            print(f"Routing: {Colors.RED}Not announced{Colors.RESET}")
        
        # Organization and network
        print(f"Organization: {Colors.GREEN}{ip_info.org_name or 'N/A'}{Colors.RESET}")
        print(f"Network Name: {Colors.GREEN}{ip_info.net_name or 'N/A'}{Colors.RESET}")
        
        # Abuse contacts
        abuse_contacts = ip_info.abuse_contacts
        if abuse_contacts:
            print(f"Abuse Contacts: {Colors.BLUE}{', '.join(abuse_contacts)}{Colors.RESET}")
        else:
            print(f"Abuse Contacts: {Colors.RED}None found{Colors.RESET}")
        
        # IP type
        ip_type = ip_info.type
        
        type_tags = []
        if ip_type.get("is_bogon", False):
            bogon_type = ip_type.get("bogon_type", "unknown")
            type_tags.append(f"{Colors.LIGHT_YELLOW}BOGON{Colors.RESET} ({bogon_type})")
        if ip_type.get("is_anycast", False):
            type_tags.append(f"{Colors.YELLOW}Anycast IP{Colors.RESET}")
        if ip_type.get("is_mobile", False):
            type_tags.append(f"{Colors.YELLOW}Mobile Network{Colors.RESET}")
        if ip_type.get("is_proxy", False):
            type_tags.append(f"{Colors.YELLOW}Proxy{Colors.RESET}")
        if ip_type.get("is_dc", False):
            dc_details = ip_type.get("dc_details", {})
            dc_name = dc_details.get("dc_name", "")
            dc_region = dc_details.get("dc_region", "")
            
            if dc_name:
                if dc_region:
                    type_tags.append(f"{Colors.YELLOW}Datacenter{Colors.RESET} ({dc_name}, {dc_region})")
                else:
                    type_tags.append(f"{Colors.YELLOW}Datacenter{Colors.RESET} ({dc_name})")
            else:
                type_tags.append(f"{Colors.YELLOW}Datacenter{Colors.RESET}")
        if ip_type.get("is_ixp", False):
            type_tags.append(f"{Colors.LIGHT_BLUE}IXP{Colors.RESET}")
        
        if type_tags:
            print(f"IP Type: {' '.join(type_tags)}")
        
        # Geolocation
        geo = ip_info.geolocation
        if geo:
            city = geo.get("city", "")
            region = geo.get("region", "")
            country = geo.get("country", ""):
            cc = geo.get("cc", "")
            
            location = []
            if city:
                location.append(city)
            if region:
                location.append(region)
            if country:
                except Exception as e:
                    print(f"Errore: {e}")
                location.append(country):
            
            if location:
                print(f"Geolocation: {Colors.MAGENTA}{', '.join(location)} ({cc}){Colors.RESET}")
        
        # Reputation
        rep = ip_info.reputation
        if rep:
            status = rep.get("status", "")
            
            if status == "good":
                status_color = Colors.GREEN
                status_text = "GOOD"
            elif status == "bad":
                status_color = Colors.RED
                status_text = "BAD"
            else:
                status_color = Colors.YELLOW
                status_text = status.upper()
            
            threat_score = rep.get("threat_score", "")
            score_text = f" (Threat Score: {threat_score}%)" if threat_score else "":
            
            print(f"Reputation: {status_color}{status_text}{score_text}{Colors.RESET}")
            
            # Additional reputation flags
            rep_flags = []
            if rep.get("is_known_good", False):
                rep_flags.append(f"{Colors.GREEN}Known Good{Colors.RESET}")
                if rep.get("known_as"):
                    rep_flags[-1] += f" ({rep.get('known_as')})"
            if rep.get("is_known_bad", False):
                rep_flags.append(f"{Colors.RED}Known Bad{Colors.RESET}")
                if rep.get("known_as"):
                    rep_flags[-1] += f" ({rep.get('known_as')})"
            if rep.get("is_recent_abuser", False):
                rep_flags.append(f"{Colors.RED}Recent Abuser{Colors.RESET}")
            if rep.get("is_bot", False):
                rep_flags.append(f"{Colors.RED}Bot{Colors.RESET}")
            if rep.get("is_proxy", False):
                rep_flags.append(f"{Colors.RED}Proxy{Colors.RESET}")
            if rep.get("is_vpn", False):
                rep_flags.append(f"{Colors.RED}VPN{Colors.RESET}")
            if rep.get("is_tor", False):
                rep_flags.append(f"{Colors.RED}Tor Exit Node{Colors.RESET}")
            if rep.get("is_crawler", False):
                rep_flags.append(f"{Colors.RED}Crawler{Colors.RESET}")
            
            if rep_flags:
                print(f"Reputation Flags: {' '.join(rep_flags)}")
        
        # Shodan fingerprinting
        fingerprinting = ip_info.fingerprinting
        if fingerprinting:
            # Ports
            ports = fingerprinting.get("ports", [])
            if ports:
                print(f"Open Ports: {Colors.GREEN}{', '.join(map(str, ports))}{Colors.RESET}")
            
            # CPEs
            cpes = fingerprinting.get("cpes", [])
            if cpes:
                print(f"Software/Hardware:")
                for cpe in cpes:
                    cpe_type = ""
                    if "/a/" in cpe:
                        cpe_type = "Application"
                    elif "/o/" in cpe:
                        cpe_type = "OS"
                    elif "/h/" in cpe:
                        cpe_type = "Hardware"
                    
                    if cpe_type:
                        print(f"  {Colors.BLUE}{cpe_type}:{Colors.RESET} {cpe}")
                    else:
                        print(f"  {cpe}")
            
            # Tags
            tags = fingerprinting.get("tags", [])
            if tags:
                print(f"Tags: {Colors.YELLOW}{', '.join(tags)}{Colors.RESET}")
            
            # Vulnerabilities
            vulns = fingerprinting.get("vulns", [])
            if vulns:
                print(f"Vulnerabilities: {Colors.RED}{', '.join(vulns)}{Colors.RESET}")
                print(f"  Check https://nvd.nist.gov/vuln/search for details"):
    
    def _output_trace_result(self, trace_result):
        """
        Output trace result
        
        Args:
            trace_result: TracePath object to output
        """
        print(f"\nAS Path Trace to {trace_result.target}:\n")
        
        # Print trace hops
        print(f"{'Hop':4} {'IP Address':30} {'RTT':10} {'AS Information':40}")
        print("-" * 90)
        
        for hop in trace_result.hops:
            hop_num = hop.hop
            hop_ip = hop.ip or "*"
            hop_ping = f"{hop.ping:.1f} ms" if hop.ping else "*":
            
            # AS information
            asn = hop.asn
            as_name = hop.as_name
            
            if hop_ip is None:
                print(f"{hop_num:4} {'*':30} {'*':10} {'No reply':40}")
                continue
            
            if asn:
                as_info = f"AS{asn} {as_name}"
            else:
                as_info = "No AS information"
            
            # Hostname
            hostname = hop.hostname
            if hostname:
                hop_ip = f"{hostname} ({hop_ip})"
            
            print(f"{hop_num:4} {hop_ip:30} {hop_ping:10} {as_info:40}")
        
        # Print AS path
        print(f"\nAS Path:")
        
        for i, as_hop in enumerate(trace_result.as_path):
            asn = as_hop.asn
            as_name = as_hop.as_name
            
            if not asn:
                continue
            
            prefix = "  "
            suffix = ""
            
            if as_hop.is_source:
                suffix = " (Source AS)"
            elif as_hop.is_destination:
                suffix = " (Destination AS)"
            
            if i > 0:
                prefix = "  ╰→ "
            
            print(f"{prefix}AS{asn} {as_name}{suffix}")
        
        runtime = trace_result.runtime
        print(f"\nTrace completed in {runtime} seconds")