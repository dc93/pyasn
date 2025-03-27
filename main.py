#!/usr/bin/env python3
"""
PyASN - Python Cross-Platform ASN Lookup Tool

A complete Python rewrite of the ASN bash script, providing autonomous system number
lookups, RPKI validation, BGP statistics, IP reputation, and traceroute functionality
in a cross-platform package that works on Windows, macOS, and Linux.
"""

import argparse
import logging
import sys
from pathlib import Path

from pyasn.core.config import Config
from pyasn.interfaces.cli import CLI
from pyasn.interfaces.web_server import WebServer

def main():
    """Main entry point for PyASN"""
    # Parse initial arguments to determine mode
    parser = argparse.ArgumentParser(description="PyASN - Network Intelligence Tool")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument("--config", type=str, help="Path to configuration file")
    parser.add_argument("--server", action="store_true", help="Run in web server mode")
    parser.add_argument("--version", action="store_true", help="Show version information")
    
    # Parse just the known args for initial setup
    args, remaining = parser.parse_known_args()
    
    # Setup configuration
    config_path = Path(args.config) if args.config else None
    config = Config(config_path, debug=args.debug)
    
    # Setup logging
    if args.debug:
        logging.basicConfig(
            level=logging.DEBUG,
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            handlers=[
                logging.FileHandler(config.log_file),
                logging.StreamHandler()
            ]
        )
    else:
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s - %(message)s"
        )
    
    # Show version info if requested
    if args.version:
        from pyasn import __version__
        print(f"PyASN version {__version__}")
        return 0
    
    # Run in web server mode if requested
    if args.server:
        server = WebServer(config)
        return server.run()
    
    # Otherwise, run in CLI mode
    cli = CLI(config)
    return cli.run(sys.argv[1:])

if __name__ == "__main__":
    sys.exit(main())