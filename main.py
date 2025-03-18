#!/usr/bin/env python3
"""
Phishing Scanner Application
----------------------------
A tool for scanning URLs for phishing indicators using various methods
including heuristic analysis, VirusTotal API, and Google Safe Browsing API.

This is the main entry point for the application.
"""

import sys
import argparse
import logging
import os
from typing import List, Optional

# Set up logging configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("phiscanner.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('phiscanner.main')

def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Phishing Link Scanner")
    
    # Add subparsers for different modes
    subparsers = parser.add_subparsers(dest='mode', help='Operating mode')
    
    # GUI mode (default)
    gui_parser = subparsers.add_parser('gui', help='Run in GUI mode')
    
    # CLI mode
    cli_parser = subparsers.add_parser('cli', help='Run in command-line mode')
    cli_parser.add_argument("urls", nargs='+', help="URLs to scan")
    cli_parser.add_argument("--vt-api-key", help="VirusTotal API Key")
    cli_parser.add_argument("--gsb-api-key", help="Google Safe Browsing API Key")
    cli_parser.add_argument("--output", help="Output report file")
    
    return parser.parse_args()

def run_gui_mode():
    """Run the application in GUI mode."""
    try:
        # Import GUI modules only when needed
        from phiscanner_ui import main as ui_main
        logger.info("Starting GUI mode")
        ui_main()
    except Exception as e:
        logger.error(f"Error starting GUI: {str(e)}")
        print(f"Error starting GUI: {str(e)}")
        sys.exit(1)

def run_cli_mode(args: argparse.Namespace):
    """Run the application in command-line mode."""
    try:
        # Import scanner
        from phiscanner import PhishingScanner, main as scanner_main
        logger.info(f"Starting CLI mode for URLs: {args.urls}")
        
        # Use the main function from phiscanner.py
        scanner_main()
    except Exception as e:
        logger.error(f"Error in CLI mode: {str(e)}")
        print(f"Error: {str(e)}")
        sys.exit(1)

def main():
    """Main entry point for the application."""
    args = parse_args()
    
    # Determine the mode
    mode = getattr(args, 'mode', 'gui')  # Default to GUI if not specified
    
    if mode == 'cli':
        run_cli_mode(args)
    else:
        run_gui_mode()

if __name__ == "__main__":
    main() 