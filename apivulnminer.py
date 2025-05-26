#!/usr/bin/env python3
"""
APIVulnMiner - Advanced API Vulnerability Scanner
Author: Shan (https://linkedin.com/in/shaniii | https://github.com/shaniidev)
Description: Automated API endpoint discovery and vulnerability testing
Version: 1.0.0
"""

import asyncio
import argparse
import sys
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse
from datetime import datetime

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from core.scanner import APIScanner
from core.config import Config
from utils.banner import show_banner
from utils.logger import setup_logger

console = Console()

def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="APIVulnMiner - Advanced API Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # If installed as system command:
  apivulnminer -u https://api.example.com
  apivulnminer -u https://api.example.com -w custom_wordlist.txt
  apivulnminer -u https://api.example.com -o html -f results.html
  apivulnminer -u https://api.example.com --threads 50 --delay 0.1

  # Or run directly (Windows/any platform):
  python apivulnminer.py -u https://api.example.com
  python apivulnminer.py -u https://api.example.com -w custom_wordlist.txt
  python apivulnminer.py -u https://api.example.com -o html -f results.html
  python apivulnminer.py -u https://api.example.com --threads 50 --delay 0.1
        """
    )
    
    # Required arguments
    parser.add_argument(
        "-u", "--url",
        required=True,
        help="Target API base URL (e.g., https://api.example.com)"
    )
    
    # Optional arguments
    parser.add_argument(
        "-w", "--wordlist",
        help="Custom wordlist file for endpoint discovery"
    )
    
    parser.add_argument(
        "-o", "--output",
        choices=["json", "html", "csv", "txt"],
        default="json",
        help="Output format (default: json)"
    )
    
    parser.add_argument(
        "-f", "--file",
        help="Output file path"
    )
    
    parser.add_argument(
        "--threads",
        type=int,
        default=20,
        help="Number of concurrent threads (default: 20)"
    )
    
    parser.add_argument(
        "--delay",
        type=float,
        default=0.05,
        help="Delay between requests in seconds (default: 0.05)"
    )
    
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="Request timeout in seconds (default: 10)"
    )
    
    parser.add_argument(
        "--headers",
        help="Custom headers as JSON string"
    )
    
    parser.add_argument(
        "--auth",
        help="Authentication token (Bearer token)"
    )
    
    parser.add_argument(
        "--proxy",
        help="Proxy URL (e.g., http://127.0.0.1:8080)"
    )
    
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output"
    )
    
    parser.add_argument(
        "--no-banner",
        action="store_true",
        help="Disable banner display"
    )
    
    return parser.parse_args()

async def async_main():
    """Async main application entry point."""
    args = parse_arguments()
    
    # Setup logging
    logger = setup_logger(verbose=args.verbose)
    
    # Show banner
    if not args.no_banner:
        show_banner()
    
    try:
        # Initialize configuration
        config = Config(
            target_url=args.url,
            wordlist_path=args.wordlist,
            threads=args.threads,
            delay=args.delay,
            timeout=args.timeout,
            headers=args.headers,
            auth_token=args.auth,
            proxy=args.proxy,
            verbose=args.verbose
        )
        
        # Validate configuration
        if not config.validate():
            console.print("[red]❌ Invalid configuration. Exiting.[/red]")
            sys.exit(1)
        
        # Initialize scanner
        scanner = APIScanner(config)
        
        # Start scanning
        console.print(f"\n[green]🚀 Starting API vulnerability scan on: {args.url}[/green]")
        
        results = await scanner.scan()
        
        # Generate output
        if args.file:
            output_file = args.file
        else:
            # Generate a unique default filename
            parsed_url = urlparse(config.target_url)
            hostname = parsed_url.hostname if parsed_url.hostname else "default_target"
            # Sanitize hostname for filename
            safe_hostname = "".join(c if c.isalnum() else "_" for c in hostname)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"apivulnminer_results_{safe_hostname}_{timestamp}.{args.output}"
            
        await scanner.generate_report(results, args.output, output_file)
        
        # Display summary
        scanner.display_summary(results)
        
        console.print(f"\n[green]✅ Scan completed! Results saved to: {output_file}[/green]")
        
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠️  Scan interrupted by user[/yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[red]❌ Error: {str(e)}[/red]")
        if args.verbose:
            console.print_exception()
        sys.exit(1)

def main():
    """Main entry point for console script."""
    asyncio.run(async_main())

if __name__ == "__main__":
    main() 