"""
Web server interface for PyASN
"""

import base64
import gzip
import json
import logging
import socket
import subprocess
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Dict, Optional, Tuple, List, Any
from urllib.parse import parse_qs, unquote, urlparse

from pyasn.core.config import Config
from pyasn.core.exceptions import PyASNError
from pyasn.core.models import (
    ASNInfo, IPInfo, TracePath, OrganizationSearchResult,
    ShodanScanResult, GeolocateResult, CountryCIDRResult
)
from pyasn.services.asn_lookup import ASNLookupService
from pyasn.services.ip_lookup import IPLookupService
from pyasn.services.trace_path import TracePathService
from pyasn.services.org_search import OrganizationSearchService
from pyasn.services.shodan_scan import ShodanScanService
from pyasn.utils.cache import Cache
from pyasn.utils.network import NetworkUtils

# HTML color codes for server mode
HTML_COLORS = {
    "white": "#cccccc",
    "black": "#1e1e1e",
    "light_gray": "#d5d5d5",
    "red": "#ff5f5f",
    "dark_red": "#b74d4d",
    "blue": "#00afd7",
    "yellow": "#afaf00",
    "green": "#00af5f",
    "dark_green": "#058505",
    "magenta": "#ff5fff"
}

class WebServer:
    """Web server interface for PyASN"""
    
    def __init__(self, config: Config):
        """
        Initialize web server interface
        
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
        
        # Server settings
        self.address = config.default_server_bind_addr_v4
        self.port = config.default_server_bind_port
        self.allowed_ips = None
        self.max_connections = 100
        self.server = None
    
    def run(self, address=None, port=None, allowed_ips=None, max_connections=None, open_browser=True) -> int:
        """
        Run the web server
        
        Args:
            address: Bind address (default: from config)
            port: Bind port (default: from config)
            allowed_ips: Allowed IPs (default: all)
            max_connections: Maximum concurrent connections (default: 100)
            open_browser: Whether to open a browser window (default: True)
            
        Returns:
            Exit code (0 for success, non-zero for error)
        """
        # Update settings if provided
        self.address = address or self.address
        self.port = port or self.port
        self.allowed_ips = allowed_ips
        self.max_connections = max_connections or self.max_connections
        
        try:
            # Create a request handler class with access to our lookup services
            context = self
            
            class ASNRequestHandler(BaseHTTPRequestHandler):
                def __init__(self, *args, **kwargs):
                    self.context = context
                    super().__init__(*args, **kwargs)
                
                def log_message(self, format, *args):
                    """Override log_message to use our logging setup"""
                    if self.context.config.debug:
                        logging.info(f"{self.address_string()} - {format % args}")
                
                def do_GET(self):
                    """Handle GET requests"""
                    # Check if client IP is allowed
                    if self.context.allowed_ips and self.client_address[0] not in self.context.allowed_ips:
                        self.send_error(403, "Forbidden")
                        return
                    
                    # Parse the path
                    parsed_path = urlparse(self.path)
                    path = parsed_path.path
                    
                    # Get query parameters
                    params = parse_qs(parsed_path.query)
                    
                    # Handle different paths
                    if path == "/":
                        self.handle_index()
                    elif path == "/asn_bookmarklet":
                        self.handle_bookmarklet()
                    elif path == "/asn_lookup":
                        self.handle_lookup()
                    elif path == "/asn_lookup_json":
                        self.handle_lookup_json()
                    elif path == "/asn_lookup_jsonp":
                        self.handle_lookup_json(pretty=True)
                    elif path == "/termbin_share":
                        self.handle_termbin_share()
                    else:
                        self.send_error(404, "Not Found")
                
                def handle_index(self):
                    """Handle index page request"""
                    self.send_response(200)
                    self.send_header("Content-type", "text/html")
                    self.end_headers()
                    
                    html = f"""
                    <html>
                    <head>
                        <title>PyASN Web Interface</title>
                        <style>
                            body {{
                                font-family: Arial, sans-serif;
                                margin: 20px;
                                line-height: 1.6;
                                background-color: {HTML_COLORS["black"]};
                                color: {HTML_COLORS["white"]};
                            }}
                            h1 {{
                                color: {HTML_COLORS["green"]};
                            }}
                            form {{
                                background-color: #2e2e2e;
                                padding: 20px;
                                border-radius: 5px;
                                margin-bottom: 20px;
                            }}
                            input[type="text"] {{
                                width: 70%;
                                padding: 10px;
                                margin-right: 10px;
                                background-color: #3e3e3e;
                                border: none;
                                color: {HTML_COLORS["white"]};
                            }}
                            button {{
                                padding: 10px 20px;
                                background-color: {HTML_COLORS["blue"]};
                                border: none;
                                color: #000;
                                cursor: pointer;
                            }}
                            .options {{
                                margin-top: 10px;
                            }}
                            .option {{
                                margin-right: 15px;
                            }}
                            a {{
                                color: {HTML_COLORS["blue"]};
                                text-decoration: none;
                            }}
                            a:hover {{
                                text-decoration: underline;
                            }}
                            .tools {{
                                display: flex;
                                flex-wrap: wrap;
                                gap: 20px;
                                margin-top: 20px;
                            }}
                            .tool {{
                                background-color: #2e2e2e;
                                padding: 15px;
                                border-radius: 5px;
                                flex: 1;
                                min-width: 200px;
                            }}
                            .tool h3 {{
                                color: {HTML_COLORS["yellow"]};
                                margin-top: 0;
                            }}
                            footer {{
                                margin-top: 40px;
                                font-size: 0.8em;
                                color: #666;
                                text-align: center;
                            }}
                        </style>
                    </head>
                    <body>
                        <h1>PyASN Web Interface</h1>
                        
                        <form action="/asn_lookup" method="get">
                            <input type="text" name="target" placeholder="Enter IP, ASN, hostname, URL, or organization name">
                            <button type="submit">Lookup</button>
                            <div class="options">
                                <label class="option"><input type="checkbox" name="trace" value="1" checked> Enable AS path tracing</label>
                                <label class="option"><input type="checkbox" name="detailed" value="1"> Show detailed trace</label>
                            </div>
                        </form>
                        
                        <div class="tools">
                            <div class="tool">
                                <h3>ASN Lookups</h3>
                                <p>Look up information about Autonomous System Numbers including BGP peers, announced prefixes, and more.</p>
                                <p>Example: <a href="/asn_lookup?target=AS15169">AS15169</a> (Google)</p>
                            </div>
                            
                            <div class="tool">
                                <h3>IP Intelligence</h3>
                                <p>Get detailed information about IP addresses including geolocation, ASN ownership, and reputation.</p>
                                <p>Example: <a href="/asn_lookup?target=8.8.8.8">8.8.8.8</a> (Google DNS)</p>
                            </div>
                            
                            <div class="tool">
                                <h3>Hostname Lookups</h3>
                                <p>Resolve hostnames to IPs and get information about each IP.</p>
                                <p>Example: <a href="/asn_lookup?target=google.com">google.com</a></p>
                            </div>
                            
                            <div class="tool">
                                <h3>Organization Search</h3>
                                <p>Find network ranges owned by an organization.</p>
                                <p>Example: <a href="/asn_lookup?target=Cloudflare">Cloudflare</a></p>
                            </div>
                        </div>
                        
                        <div class="tools">
                            <div class="tool">
                                <h3>Tools</h3>
                                <ul>
                                    <li><a href="/asn_bookmarklet">ASN Lookup Bookmarklet</a> - Add a bookmarklet to your browser for quick lookups</li>
                                </ul>
                            </div>
                        </div>
                        
                        <footer>
                            PyASN Web Interface | Server: {self.context.address}:{self.context.port}
                        </footer>
                    </body>
                    </html>
                    """
                    
                    self.wfile.write(html.encode())
                
                def handle_bookmarklet(self):
                    """Handle bookmarklet page request"""
                    self.send_response(200)
                    self.send_header("Content-type", "text/html")
                    self.end_headers()
                    
                    # Generate bookmarklet code
                    js_bookmarklet = (
                        f'javascript:(function(){{'
                        f'var asnserver="{self.context.address}:{self.context.port}",'
                        f'target=window.location.hostname,'
                        f'width=screen.width-screen.width/7,height=screen.height-screen.height/4,'
                        f'left=window.innerWidth/2-width/2,top=window.innerHeight/2-height/2;'
                        f'window.open("http://"+asnserver+"/asn_lookup?target="+target,"newWindow",'
                        f'"width="+width+",height="+height+",top="+top+",left="+left)}})();'
                    )
                    
                    # HTML page
                    html = f"""
                    <html>
                    <head>
                        <title>ASN Lookup Bookmarklet Setup</title>
                        <style>
                            body {{
                                font-family: Arial, sans-serif;
                                margin: 20px;
                                line-height: 1.6;
                                background-color: {HTML_COLORS["black"]};
                                color: {HTML_COLORS["white"]};
                            }}
                            h1 {{
                                color: {HTML_COLORS["green"]};
                            }}
                            a.bookmark {{
                                display: inline-block;
                                background-color: {HTML_COLORS["yellow"]};
                                color: #000000;
                                padding: 10px 20px;
                                margin: 20px 0;
                                text-decoration: none;
                                font-weight: bold;
                                font-size: 1.5em;
                                border-radius: 5px;
                            }}
                            .instructions {{
                                background-color: #2e2e2e;
                                padding: 15px;
                                border-radius: 5px;
                                margin-top: 20px;
                            }}
                            footer {{
                                margin-top: 30px;
                                font-size: 0.8em;
                                color: #666;
                            }}
                            a {{
                                color: {HTML_COLORS["blue"]};
                                text-decoration: none;
                            }}
                            a:hover {{
                                text-decoration: underline;
                            }}
                        </style>
                    </head>
                    <body>
                        <h1>ASN Lookup Bookmarklet Setup</h1>
                        
                        <div class="instructions">
                            <p>1. Drag and drop the yellow button below to your bookmarks toolbar:</p>
                            
                            <a class="bookmark" href='{js_bookmarklet}'>ASN LOOKUP</a>
                            
                            <p>2. While browsing any website, click the bookmark to perform an ASN lookup on that site.</p>
                        </div>
                        
                        <div class="instructions">
                            <h2>How it works</h2>
                            <p>The bookmarklet extracts the hostname of the current website and sends it to this ASN lookup server.
                            The server performs a lookup and displays the results.</p>
                        </div>
                        
                        <footer>
                            <a href="/">Back to Home</a> | PyASN Web Interface | Running at {self.context.address}:{self.context.port}
                        </footer>
                    </body>
                    </html>
                    """
                    
                    self.wfile.write(html.encode())
                
                def handle_lookup(self):
                    """Handle asn_lookup requests"""
                    # Parse query parameters
                    parsed_path = urlparse(self.path)
                    params = parse_qs(parsed_path.query)
                    
                    # Extract target from query params
                    target = params.get("target", [""])[0]
                    if not target:
                        self.redirect_to_home("Missing target")
                        return
                    
                    # Extract other parameters
                    trace_enabled = params.get("trace", ["1"])[0] == "1"
                    detailed_trace = params.get("detailed", ["0"])[0] == "1"
                    
                    # Update config for this request
                    self.context.config.mtr_tracing = trace_enabled
                    self.context.config.detailed_trace = detailed_trace
                    
                    # Send response headers
                    self.send_response(200)
                    self.send_header("Content-type", "text/html")
                    self.end_headers()
                    
                    # HTML header
                    html_head = f""""
                    <html>
                    <head>
                        <title>ASN Lookup: {target}</title>
                        <style>
                            body {{
                                font-family: monospace;
                                line-height: 1.2;
                                background-color: {HTML_COLORS["black"]};
                                color: {HTML_COLORS["white"]};
                                padding: 20px;
                            }}
                            pre {{
                                white-space: pre-wrap;
                            }}
                            .header {{
                                margin: 10px 0;
                                padding: 10px;
                                background-color: #2e2e2e;
                                border-radius: 5px;
                            }}
                            .result {{
                                margin-top: 20px;
                            }}
                            .loading {{
                                text-align: center;
                                margin: 20px 0;
                            }}
                            table {{
                                width: 100%;
                                border-collapse: collapse;
                                margin: 10px 0;
                            }}
                            th, td {{
                                padding: 8px;
                                text-align: left;
                                border-bottom: 1px solid #444;
                            }}
                            th {{
                                background-color: {HTML_COLORS["blue"]};
                                color: #000;
                            }}
                            a {{
                                color: {HTML_COLORS["blue"]};
                                text-decoration: none;
                            }}
                            a:hover {{
                                text-decoration: underline;
                            }}
                            .green {{ color: {HTML_COLORS["green"]}; }}
                            .red {{ color: {HTML_COLORS["red"]}; }}
                            .blue {{ color: {HTML_COLORS["blue"]}; }}
                            .yellow {{ color: {HTML_COLORS["yellow"]}; }}
                            .magenta {{ color: {HTML_COLORS["magenta"]}; }}
                        </style>
                        <script>
                            window.onload = function() {{
                                document.getElementById('loading').style.display = 'none';
                            }};
                        </script>
                    </head>
                    <body>
                        <div class="header">
                            <h1>ASN Lookup Results: {target}</h1>
                            <p>Server: {self.context.address}:{self.context.port} | Time: {time.strftime('%Y-%m-%d %H:%M:%S')}</p>
                            <p><a href="/">Home</a> | <a href="/asn_lookup_json?target={target}">View as JSON</a></p>
                        </div>
                        
                        <div id="loading" class="loading">
                            <p>Loading... Please wait.</p>
                        </div>
                        
                        <div class="result">
                            <pre>
                    """
                    
                    self.wfile.write(html_head.encode())
                    
                    # Perform lookup based on target type
                    try:
                        # First determine the type of target
                        if self.context.network_utils.is_asn(target):
                            asn_num = self.context.network_utils.normalize_asn(target)
                            asn_info = self.context.asn_lookup.lookup_asn(asn_num)
                            
                            # Generate HTML output
                            output = self.generate_asn_html(asn_info)
                            self.wfile.write(output.encode())
                        
                        elif self.context.network_utils.is_valid_ip(target):
                            # IP lookup
                            ip_info = self.context.ip_lookup.lookup_ip(target)
                            
                            # Generate HTML output
                            output = self.generate_ip_html(ip_info)
                            self.wfile.write(output.encode())
                            
                            # Perform trace if enabled
                            if self.context.config.mtr_tracing:
                                trace_result = self.context.trace_path.trace_as_path(target)
                                trace_output = self.generate_trace_html(trace_result)
                                self.wfile.write(trace_output.encode())
                        
                        elif self.context.network_utils.is_url(target):
                            hostname = self.context.network_utils.extract_hostname_from_url(target)
                            self.handle_hostname_lookup(hostname)
                        
                        elif self.context.network_utils.is_hostname(target):
                            self.handle_hostname_lookup(target)
                        
                        else:
                            # Assume it's an organization name'
                            result = self.context.org_search.search_by_org(target)
                            output = self.generate_org_html(result)
                            self.wfile.write(output.encode())
                    
                    except PyASNError as e:
                        error_msg = f"Error performing lookup: {str(e)}"
                        self.wfile.write(f"<div class='red'>{error_msg}</div>".encode())
                    except Exception as e:
                        logging.error(f"Unexpected error during lookup: {e}", exc_info=True)
                        error_msg = f"An unexpected error occurred: {str(e)}"
                        self.wfile.write(f"<div class='red'>{error_msg}</div>".encode())
                    
                    # HTML footer
                    html_footer = """
                            </pre>
                        </div>
                        
                        <div class="header" style="margin-top: 20px; text-align: center;">
                            <p>PyASN Web Interface</p>
                            <p>
                                <a href="#" onclick="window.location.href='/termbin_share?' + encodeURIComponent(document.documentElement.outerHTML)">
                                    Share Results
                                </a>
                            </p>
                        </div>
                    </body>
                    </html>
                    """
                    
                    self.wfile.write(html_footer.encode())
                
                def handle_hostname_lookup(self, hostname):
                    """Handle hostname lookup"""
                    # Resolve hostname to IPs
                    self.wfile.write(f"<div class='blue'>Resolving \"{hostname}\"...</div>\n".encode())
                    try:
                        ips = self.context.network_utils.resolve_hostname(hostname)
                        
                        self.wfile.write(f"<div class='blue'>Found {len(ips)} IP address(es):</div>\n".encode())
                        for ip in ips:
                            self.wfile.write(f"  <a href='/asn_lookup?target={ip}'>{ip}</a>\n".encode())
                        
                        # For each IP, get information
                        for ip in ips:
                            self.wfile.write(f"\n<hr>\n".encode())
                            ip_info = self.context.ip_lookup.lookup_ip(ip)
                            output = self.generate_ip_html(ip_info)
                            self.wfile.write(output.encode())
                        
                        # If tracing is enabled, trace the first IP
                        if self.context.config.mtr_tracing and ips:
                            trace_result = self.context.trace_path.trace_as_path(ips[0])
                            trace_output = self.generate_trace_html(trace_result)
                            self.wfile.write(trace_output.encode())
                            
                    except PyASNError as e:
                        self.wfile.write(f"<div class='red'>Error: {str(e)}</div>\n".encode())
                
                def handle_lookup_json(self, pretty=False):
                    """Handle JSON lookup requests"""
                    # Parse query parameters
                    parsed_path = urlparse(self.path)
                    params = parse_qs(parsed_path.query)
                    
                    # Extract target from query params
                    target = params.get("target", [""])[0]
                    if not target:
                        self.send_error(400, "Missing target")
                        return
                    
                    # Extract other parameters
                    trace_enabled = params.get("trace", ["1"])[0] == "1"
                    
                    # Update config for this request
                    self.context.config.mtr_tracing = trace_enabled
                    
                    # Send response headers
                    self.send_response(200)
                    self.send_header("Content-type", "application/json")
                    self.end_headers()
                    
                    # Prepare response data
                    response = {
                        "query": target,
                        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "version": "1.0.0"
                    }
                    
                    try:
                        # Determine target type and perform lookup
                        if self.context.network_utils.is_asn(target):
                            asn_num = self.context.network_utils.normalize_asn(target)
                            asn_info = self.context.asn_lookup.lookup_asn(asn_num)
                            response["type"] = "asn"
                            response["result"] = asn_info.__dict__
                        
                        elif self.context.network_utils.is_valid_ip(target):
                            ip_info = self.context.ip_lookup.lookup_ip(target)
                            response["type"] = "ip"
                            response["result"] = ip_info.__dict__
                            
                            # Add trace result if enabled
                            if self.context.config.mtr_tracing:
                                trace_result = self.context.trace_path.trace_as_path(target)
                                response["trace"] = trace_result.__dict__
                        
                        elif self.context.network_utils.is_url(target):
                            hostname = self.context.network_utils.extract_hostname_from_url(target)
                            ips = self.context.network_utils.resolve_hostname(hostname)
                            
                            response["type"] = "url"
                            response["hostname"] = hostname
                            response["ips"] = ips
                            
                            if ips:
                                ip_results = []
                                for ip in ips:
                                    ip_info = self.context.ip_lookup.lookup_ip(ip)
                                    ip_results.append(ip_info.__dict__)
                                
                                response["results"] = ip_results
                                
                                # Add trace for first IP
                                if self.context.config.mtr_tracing:
                                    trace_result = self.context.trace_path.trace_as_path(ips[0])
                                    response["trace"] = trace_result.__dict__
                        
                        elif self.context.network_utils.is_hostname(target):
                            ips = self.context.network_utils.resolve_hostname(target)
                            
                            response["type"] = "hostname"
                            response["ips"] = ips
                            
                            if ips:
                                ip_results = []
                                for ip in ips:
                                    ip_info = self.context.ip_lookup.lookup_ip(ip)
                                    ip_results.append(ip_info.__dict__)
                                
                                response["results"] = ip_results
                                
                                # Add trace for first IP
                                if self.context.config.mtr_tracing:
                                    trace_result = self.context.trace_path.trace_as_path(ips[0])
                                    response["trace"] = trace_result.__dict__
                        
                        else:
                            # Assume it's an organization name'
                            result = self.context.org_search.search_by_org(target)
                            response["type"] = "organization"
                            response["result"] = result.__dict__
                    
                    except PyASNError as e:
                        response["error"] = str(e)
                    except Exception as e:
                        logging.error(f"Unexpected error during JSON lookup: {e}", exc_info=True)
                        response["error"] = f"An unexpected error occurred: {str(e)}"
                    
                    # Output JSON
                    if pretty:
                        json_output = json.dumps(response, indent=2, default=str)
                    else:
                        json_output = json.dumps(response, default=str)
                    
                    self.wfile.write(json_output.encode())
                
                def handle_termbin_share(self):
                    """Handle termbin share requests"""
                    # Read the content to share
                    content_length = int(self.headers.get('Content-Length', 0))
                    content = self.rfile.read(content_length).decode() if content_length > 0 else ""
                    
                    # Send response headers
                    self.send_response(200)
                    self.send_header("Content-type", "text/plain")
                    self.end_headers()
                    
                    if not content:
                        self.wfile.write("Error: No content to share".encode())
                        return
                    
                    try:
                        # Use nc to share on termbin
                        # This requires netcat to be installed on the system
                        process = subprocess.Popen(
                            ["nc", "termbin.com", "9999"],
                            stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE
                        )
                        
                        # Send content to termbin
                        stdout, stderr = process.communicate(input=content.encode(), timeout=10)
                        
                        if process.returncode == 0:
                            # Return the termbin URL
                            termbin_url = stdout.decode().strip()
                            self.wfile.write(termbin_url.encode())
                        else:
                            # Return error
                            self.wfile.write(f"Error: {stderr.decode()}".encode())
                    
                    except Exception as e:
                        self.wfile.write(f"Error: {str(e)}".encode())
                
                def redirect_to_home(self, message=None):
                    """Redirect to home page with optional message"""
                    self.send_response(302)
                    redirect_url = "/"
                    if message:
                        redirect_url += f"?message={message}"
                    self.send_header("Location", redirect_url)
                    self.end_headers()
                
                def generate_asn_html(self, asn_info):
                    """Generate HTML for ASN information"""
                    asn = asn_info.asn
                    asname = asn_info.asname
                    
                    output = f"<h2>ASN Information for AS{asn}</h2>\n\n"
                    
                    # Basic information
                    output += f"<div><span class='red'>ASN:</span> AS{asn}</div>\n"
                    output += f"<div><span class='green'>ASN Name:</span> {asname}</div>\n"
                    output += f"<div><span class='yellow'>Organization:</span> {asn_info.org or 'N/A'}</div>\n"
                    output += f"<div><span class='yellow'>Holder:</span> {asn_info.holder or 'N/A'}</div>\n"
                    
                    # CAIDA rank
                    rank = asn_info.asrank
                    output += f"<div><span class='blue'>CAIDA AS Rank:</span> #{rank}</div>\n"
                    
                    # Registration date
                    reg_date = asn_info.registration_date or "N/A"
                    output += f"<div><span class='blue'>Registration Date:</span> {reg_date}</div>\n"
                    
                    # Abuse contacts
                    abuse_contacts = asn_info.abuse_contacts
                    if abuse_contacts:
                        output += f"<div><span class='blue'>Abuse Contacts:</span> {', '.join(abuse_contacts)}</div>\n"
                    else:
                        output += f"<div><span class='red'>Abuse Contacts:</span> None found</div>\n"
                    
                    # IXP presence
                    ixp_presence = asn_info.ixp_presence
                    if ixp_presence:
                        output += f"\n<h3>IXP Presence ({len(ixp_presence)}):</h3>\n<ul>\n"
                        for ixp in ixp_presence:
                            output += f"<li class='blue'>{ixp}</li>\n"
                        output += "</ul>\n"
                    else:
                        output += f"\n<h3>IXP Presence: <span class='red'>None</span></h3>\n"
                    
                    # BGP statistics
                    output += f"\n<h3>BGP Statistics:</h3>\n"
                    output += f"<div><span class='green'>IPv4 Prefixes:</span> {asn_info.prefix_count_v4}</div>\n"
                    output += f"<div><span class='yellow'>IPv6 Prefixes:</span> {asn_info.prefix_count_v6}</div>\n"
                    output += f"<div><span class='green'>BGP Peer Count:</span> {asn_info.bgp_peer_count}</div>\n"
                    
                    # BGP incidents
                    hijacks = asn_info.bgp_hijack_incidents
                    output += f"\n<h3>BGP Hijack Incidents (past year):</h3>\n"
                    output += f"<div><span class='red'>Total:</span> {hijacks.get('total', 0)}</div>\n"
                    output += f"<div><span class='red'>As Hijacker:</span> {hijacks.get('as_hijacker', 0)}</div>\n"
                    output += f"<div><span class='red'>As Victim:</span> {hijacks.get('as_victim', 0)}</div>\n"
                    
                    leaks = asn_info.bgp_leak_incidents
                    output += f"\n<h3>BGP Route Leak Incidents (past year):</h3>\n"
                    output += f"<div><span class='yellow'>Total:</span> {leaks.get('total', 0)}</div>\n"
                    
                    # BGP peers
                    upstream = asn_info.bgp_peers.get("upstream", [])
                    downstream = asn_info.bgp_peers.get("downstream", [])
                    uncertain = asn_info.bgp_peers.get("uncertain", [])
                    
                    output += f"\n<h3>BGP Peering Relationships:</h3>\n"
                    
                    output += f"\n<h4>Upstream Peers ({len(upstream)}):</h4>\n<ul>\n"
                    for i, peer in enumerate(upstream[:10]):
                        output += f"<li class='green'><a href='/asn_lookup?target=AS{peer}'>AS{peer}</a></li>\n"
                    if len(upstream) > 10:
                        output += f"<li>...and {len(upstream) - 10} more</li>\n"
                    output += "</ul>\n"
                    
                    output += f"\n<h4>Downstream Peers ({len(downstream)}):</h4>\n<ul>\n"
                    for i, peer in enumerate(downstream[:10]):
                        output += f"<li class='yellow'><a href='/asn_lookup?target=AS{peer}'>AS{peer}</a></li>\n"
                    if len(downstream) > 10:
                        output += f"<li>...and {len(downstream) - 10} more</li>\n"
                    output += "</ul>\n"
                    
                    output += f"\n<h4>Uncertain Peers ({len(uncertain)}):</h4>\n<ul>\n"
                    for i, peer in enumerate(uncertain[:10]):
                        output += f"<li><a href='/asn_lookup?target=AS{peer}'>AS{peer}</a></li>\n"
                    if len(uncertain) > 10:
                        output += f"<li>...and {len(uncertain) - 10} more</li>\n"
                    output += "</ul>\n"
                    
                    # Announced prefixes
                    prefixes = asn_info.announced_prefixes
                    
                    output += f"\n<h3>Announced IPv4 Prefixes ({len(prefixes.get('v4', []))}):</h3>\n<ul>\n"
                    for i, prefix in enumerate(prefixes.get("v4", [])[:20]):
                        output += f"<li class='green'><a href='/asn_lookup?target={prefix}'>{prefix}</a></li>\n"
                    if len(prefixes.get("v4", [])) > 20:
                        output += f"<li>...and {len(prefixes.get('v4', [])) - 20} more</li>\n"
                    output += "</ul>\n"
                    
                    output += f"\n<h3>Announced IPv6 Prefixes ({len(prefixes.get('v6', []))}):</h3>\n<ul>\n"
                    for i, prefix in enumerate(prefixes.get("v6", [])[:20]):
                        output += f"<li class='yellow'><a href='/asn_lookup?target={prefix}'>{prefix}</a></li>\n"
                    if len(prefixes.get("v6", [])) > 20:
                        output += f"<li>...and {len(prefixes.get('v6', [])) - 20} more</li>\n"
                    output += "</ul>\n"
                    
                    return output
                
                def generate_ip_html(self, ip_info):
                    """Generate HTML for IP information"""
                    ip = ip_info.ip
                    ip_version = ip_info.ip_version
                    
                    output = f"<h2>IP Information for {ip} (IPv{ip_version})</h2>\n\n"
                    
                    # PTR record
                    ptr = ip_info.reverse or "None"
                    output += f"<div><span class='blue'>PTR Record:</span> {ptr}</div>\n"
                    
                    # Routing information
                    routing = ip_info.routing
                    if routing.get("is_announced", False):
                        asn = routing.get('as_number', 'N/A')
                        asname = routing.get('as_name', 'N/A')
                        output += f"<div><span class='red'>ASN:</span> <a href='/asn_lookup?target=AS{asn}'>AS{asn}</a> <span class='green'>({asname})</span></div>\n"
                        output += f"<div><span class='yellow'>Network Range:</span> <a href='/asn_lookup?target={routing.get('route', 'N/A')}'>{routing.get('route', 'N/A')}</a></div>\n"
                        
                        # RPKI validity
                        validity = routing.get("roa_validity", "unknown")
                        validity_class = "green" if validity == "valid" else "red" if validity == "invalid" else "yellow"
                        
                        output += f"<div><span class='blue'>RPKI Validity:</span> <span class='{validity_class}'>{validity.upper()}</span> ({routing.get('roa_count', '0')} ROAs found)</div>\n"
                    else:
                        output += f"<div><span class='red'>Routing:</span> Not announced</div>\n"
                    
                    # Organization and network
                    output += f"<div><span class='green'>Organization:</span> {ip_info.org_name or 'N/A'}</div>\n"
                    output += f"<div><span class='green'>Network Name:</span> {ip_info.net_name or 'N/A'}</div>\n"
                    
                    # Abuse contacts
                    abuse_contacts = ip_info.abuse_contacts
                    if abuse_contacts:
                        output += f"<div><span class='blue'>Abuse Contacts:</span> {', '.join(abuse_contacts)}</div>\n"
                    else:
                        output += f"<div><span class='red'>Abuse Contacts:</span> None found</div>\n"
                    
                    # IP type
                    ip_type = ip_info.type
                    
                    type_tags = []
                    if ip_type.get("is_bogon", False):
                        bogon_type = ip_type.get("bogon_type", "unknown")
                        type_tags.append(f"<span class='yellow'>BOGON</span> ({bogon_type})")
                    if ip_type.get("is_anycast", False):
                        type_tags.append(f"<span class='yellow'>Anycast IP</span>")
                    if ip_type.get("is_mobile", False):
                        type_tags.append(f"<span class='yellow'>Mobile Network</span>")
                    if ip_type.get("is_proxy", False):
                        type_tags.append(f"<span class='yellow'>Proxy</span>")
                    if ip_type.get("is_dc", False):
                        dc_details = ip_type.get("dc_details", {})
                        dc_name = dc_details.get("dc_name", "")
                        dc_region = dc_details.get("dc_region", "")
                        
                        if dc_name:
                            if dc_region:
                                type_tags.append(f"<span class='yellow'>Datacenter</span> ({dc_name}, {dc_region})")
                            else:
                                type_tags.append(f"<span class='yellow'>Datacenter</span> ({dc_name})")
                        else:
                            type_tags.append(f"<span class='yellow'>Datacenter</span>")
                    if ip_type.get("is_ixp", False):
                        type_tags.append(f"<span class='blue'>IXP</span>")
                    
                    if type_tags:
                        output += f"<div><span class='blue'>IP Type:</span> {' '.join(type_tags)}</div>\n"
                    
                    # Geolocation
                    geo = ip_info.geolocation
                    if geo:
                        city = geo.get("city", "")
                        region = geo.get("region", "")
                        country = geo.get("country", "")
                        cc = geo.get("cc", "")
                        
                        location = []
                        if city:
                            location.append(city)
                        if region:
                            location.append(region)
                        if country:
                            location.append(country)
                        
                        if location:
                            output += f"<div><span class='blue'>Geolocation:</span> <span class='magenta'>{', '.join(location)} ({cc})</span></div>\n"
                    
                    # Reputation
                    rep = ip_info.reputation
                    if rep:
                        status = rep.get("status", "")
                        
                        if status == "good":
                            status_class = "green"
                            status_text = "GOOD"
                        elif status == "bad":
                            status_class = "red"
                            status_text = "BAD"
                        else:
                            status_class = "yellow"
                            status_text = status.upper()
                        
                        threat_score = rep.get("threat_score", "")
                        score_text = f" (Threat Score: {threat_score}%)" if threat_score else ""
                        
                        output += f"<div><span class='blue'>Reputation:</span> <span class='{status_class}'>{status_text}{score_text}</span></div>\n"
                        
                        # Additional reputation flags
                        rep_flags = []
                        if rep.get("is_known_good", False):
                            rep_flags.append(f"<span class='green'>Known Good</span>")
                            if rep.get("known_as"):
                                rep_flags[-1] += f" ({rep.get('known_as')})"
                        if rep.get("is_known_bad", False):
                            rep_flags.append(f"<span class='red'>Known Bad</span>")
                            if rep.get("known_as"):
                                rep_flags[-1] += f" ({rep.get('known_as')})"
                        if rep.get("is_recent_abuser", False):
                            rep_flags.append(f"<span class='red'>Recent Abuser</span>")
                        if rep.get("is_bot", False):
                            rep_flags.append(f"<span class='red'>Bot</span>")
                        if rep.get("is_proxy", False):
                            rep_flags.append(f"<span class='red'>Proxy</span>")
                        if rep.get("is_vpn", False):
                            rep_flags.append(f"<span class='red'>VPN</span>")
                        if rep.get("is_tor", False):
                            rep_flags.append(f"<span class='red'>Tor Exit Node</span>")
                        if rep.get("is_crawler", False):
                            rep_flags.append(f"<span class='red'>Crawler</span>")
                        
                        if rep_flags:
                            output += f"<div><span class='blue'>Reputation Flags:</span> {' '.join(rep_flags)}</div>\n"
                    
                    # Shodan fingerprinting
                    fingerprinting = ip_info.fingerprinting
                    if fingerprinting:
                        # Ports
                        ports = fingerprinting.get("ports", [])
                        if ports:
                            output += f"<div><span class='blue'>Open Ports:</span> <span class='green'>{', '.join(map(str, ports))}</span></div>\n"
                        
                        # CPEs
                        cpes = fingerprinting.get("cpes", [])
                        if cpes:
                            output += f"<h3>Software/Hardware:</h3>\n<ul>\n"
                            for cpe in cpes:
                                cpe_type = ""
                                if "/a/" in cpe:
                                    cpe_type = "Application"
                                elif "/o/" in cpe:
                                    cpe_type = "OS"
                                elif "/h/" in cpe:
                                    cpe_type = "Hardware"
                                
                                if cpe_type:
                                    output += f"<li><span class='blue'>{cpe_type}:</span> {cpe}</li>\n"
                                else:
                                    output += f"<li>{cpe}</li>\n"
                            output += "</ul>\n"
                        
                        # Tags
                        tags = fingerprinting.get("tags", [])
                        if tags:
                            output += f"<div><span class='blue'>Tags:</span> <span class='yellow'>{', '.join(tags)}</span></div>\n"
                        
                        # Vulnerabilities
                        vulns = fingerprinting.get("vulns", [])
                        if vulns:
                            output += f"<div><span class='blue'>Vulnerabilities:</span> <span class='red'>{', '.join(vulns)}</span></div>\n"
                            output += f"<div>Check <a href='https://nvd.nist.gov/vuln/search' target='_blank'>https://nvd.nist.gov/vuln/search</a> for details</div>\n"
                    
                    return output
                
                def generate_trace_html(self, trace_result):
                    """Generate HTML for trace result"""
                    output = f"<h2>AS Path Trace to {trace_result.target}</h2>\n\n"
                    
                    # Create trace table
                    output += "<table>\n"
                    output += "<tr><th>Hop</th><th>IP Address</th><th>RTT</th><th>AS Information</th></tr>\n"
                    
                    for hop in trace_result.hops:
                        hop_num = hop.hop
                        hop_ip = hop.ip or "*"
                        hop_ping = f"{hop.ping:.1f} ms" if hop.ping else "*"
                        
                        # AS information
                        asn = hop.asn
                        as_name = hop.as_name
                        
                        if hop_ip == "*":
                            output += f"<tr><td>{hop_num}</td><td>*</td><td>*</td><td>No reply</td></tr>\n"
                            continue
                        
                        if asn:
                            as_info = f"<a href='/asn_lookup?target=AS{asn}'>AS{asn}</a> {as_name}"
                        else:
                            as_info = "No AS information"
                        
                        # Hostname
                        hostname = hop.hostname
                        if hostname:
                            hop_ip_display = f"{hostname} (<a href='/asn_lookup?target={hop_ip}'>{hop_ip}</a>)"
                        else:
                            hop_ip_display = f"<a href='/asn_lookup?target={hop_ip}'>{hop_ip}</a>"
                        
                        output += f"<tr><td>{hop_num}</td><td>{hop_ip_display}</td><td>{hop_ping}</td><td>{as_info}</td></tr>\n"
                    
                    output += "</table>\n"
                    
                    # Print AS path
                    output += f"<h3>AS Path:</h3>\n<ul style='list-style-type: none;'>\n"
                    
                    for i, as_hop in enumerate(trace_result.as_path):
                        asn = as_hop.asn
                        as_name = as_hop.as_name
                        
                        if not asn:
                            continue
                        
                        prefix = "&nbsp;&nbsp;"
                        suffix = ""
                        
                        if as_hop.is_source:
                            suffix = " (Source AS)"
                        elif as_hop.is_destination:
                            suffix = " (Destination AS)"
                        
                        if i > 0:
                            prefix = "&nbsp;&nbsp;╰→ "
                        
                        output += f"<li>{prefix}<a href='/asn_lookup?target=AS{asn}'>AS{asn}</a> {as_name}{suffix}</li>\n"
                    
                    output += "</ul>\n"
                    
                    runtime = trace_result.runtime
                    output += f"<div>Trace completed in {runtime} seconds</div>\n"
                    
                    return output
                
                def generate_org_html(self, result):
                    """Generate HTML for organization search results"""
                    output = f"<h2>Organization search results for \"{result.query}\"</h2>\n\n"
                    
                    if not result.matches:
                        output += "<div class='red'>No matching organizations found.</div>\n"
                        return output
                    
                    # Show found organizations
                    output += f"<h3>Found Organizations:</h3>\n<ul>\n"
                    for org in result.matches:
                        output += f"<li><a href='/asn_lookup?target={org}'>{org}</a></li>\n"
                    output += "</ul>\n"
                    
                    # Use the first organization for the results
                    org_name = result.matches[0]
                    
                    # Print network ranges
                    output += f"<h3>Network ranges for {org_name}:</h3>\n"
                    
                    output += "<h4>IPv4 networks:</h4>\n"
                    if result.ipv4_networks:
                        output += "<ul>\n"
                        for network in result.ipv4_networks:
                            reg_date = network.get("registration_date", "")
                            net_type = f" ({network['net_type']})" if network.get("net_type") else ""
                            
                            output += f"<li><a href='/asn_lookup?target={network['prefix']}'>{network['prefix']}</a> - {network['net_name']}{net_type}</li>\n"
                            if reg_date:
                                output += f"<ul><li>Registered: {reg_date}</li></ul>\n"
                        output += "</ul>\n"
                    else:
                        output += "<div class='red'>No IPv4 networks found</div>\n"
                    
                    output += "<h4>IPv6 networks:</h4>\n"
                    if result.ipv6_networks:
                        output += "<ul>\n"
                        for network in result.ipv6_networks:
                            reg_date = network.get("registration_date", "")
                            net_type = f" ({network['net_type']})" if network.get("net_type") else ""
                            
                            output += f"<li><a href='/asn_lookup?target={network['prefix']}'>{network['prefix']}</a> - {network['net_name']}{net_type}</li>\n"
                            if reg_date:
                                output += f"<ul><li>Registered: {reg_date}</li></ul>\n"
                        output += "</ul>\n"
                    else:
                        output += "<div class='red'>No IPv6 networks found</div>\n"
                    
                    return output
            
            # Create and configure the HTTP server
            self.server = HTTPServer((self.address, self.port), ASNRequestHandler)
            
            # Start the server in a separate thread
            server_thread = threading.Thread(target=self._run_server)
            server_thread.daemon = True
            server_thread.start()
            
            # Log server startup message
            print(f"Starting PyASN Web Server on {self.address}:{self.port}")
            print(f"Visit http://{self.address}:{self.port}/ to use the web interface")
            print(f"Visit http://{self.address}:{self.port}/asn_bookmarklet to set up the bookmarklet")
            print("Press Ctrl+C to stop the server")
            
            # Open browser if requested
            if open_browser:
                webbrowser.open(f"http://{self.address}:{self.port}/")
            
            # Wait for Ctrl+C
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                print("\nShutting down server...")
                self.stop()
            
            return 0
            
        except socket.error as e:
            if e.errno == 98:  # Address already in use
                print(f"Error: Port {self.port} is already in use.")
            else:
                print(f"Socket error: {e}")
            return 1
        except Exception as e:
            print(f"Error starting server: {e}")
            return 1
    
    def _run_server(self):
        """Run the HTTP server"""
        try:
            self.server.serve_forever()
        except Exception as e:
            logging.error(f"Server error: {e}")
    
    def stop(self):
        """Stop the HTTP server"""
        if self.server:
            self.server.shutdown()
            self.server.server_close()