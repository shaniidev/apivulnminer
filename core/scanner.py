"""
Core API Scanner Module
Handles endpoint discovery and vulnerability testing
"""

import asyncio
import json
import time
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse
from dataclasses import dataclass, asdict
from datetime import datetime

import httpx
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.table import Table
from rich.panel import Panel

from .config import Config
from .wordlists import WordlistManager
from .vulnerabilities import VulnerabilityTester
from .endpoints import EndpointDiscovery
from utils.logger import get_logger

console = Console()
logger = get_logger(__name__)

@dataclass
class ScanResult:
    """Represents a scan result for an endpoint."""
    endpoint: str
    method: str
    status_code: int
    response_time: float
    content_length: int
    vulnerabilities: List[Dict]
    headers: Dict[str, str]
    timestamp: str
    severity: str = "info"

@dataclass
class ScanSummary:
    """Summary of the entire scan."""
    total_endpoints_tested: int
    endpoints_found: int
    vulnerabilities_found: int
    high_severity: int
    medium_severity: int
    low_severity: int
    scan_duration: float
    target_url: str
    timestamp: str

class APIScanner:
    """Main API vulnerability scanner class."""
    
    def __init__(self, config: Config):
        self.config = config
        self.client: Optional[httpx.AsyncClient] = None
        self.wordlist_manager = WordlistManager()
        self.vuln_tester = VulnerabilityTester()
        self.endpoint_discovery = EndpointDiscovery()
        self.results: List[ScanResult] = []
        self.discovered_endpoints: Set[str] = set()
        
    async def __aenter__(self):
        """Async context manager entry."""
        await self._setup_client()
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self.client:
            await self.client.aclose()
    
    async def _setup_client(self):
        """Setup HTTP client with configuration."""
        headers = {
            "User-Agent": "APIVulnMiner/1.0 (Security Scanner)",
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "en-US,en;q=0.9",
        }
        
        # Add custom headers
        if self.config.headers:
            try:
                custom_headers = json.loads(self.config.headers)
                headers.update(custom_headers)
            except json.JSONDecodeError:
                logger.warning("Invalid JSON in custom headers, ignoring")
        
        # Add authentication
        if self.config.auth_token:
            headers["Authorization"] = f"Bearer {self.config.auth_token}"
        
        # Setup client
        client_kwargs = {
            "headers": headers,
            "timeout": self.config.timeout,
            "verify": False,  # For testing purposes
            "follow_redirects": True
        }
        
        # Add proxy if configured
        if self.config.proxy:
            client_kwargs["proxy"] = self.config.proxy
            
        self.client = httpx.AsyncClient(**client_kwargs)
    
    async def scan(self) -> List[ScanResult]:
        """Main scanning method."""
        start_time = time.time()
        
        async with self:
            # Step 1: Load wordlists
            console.print("[cyan]📋 Loading wordlists...[/cyan]")
            wordlists = await self.wordlist_manager.load_wordlists(self.config.wordlist_path)
            
            # Step 2: Discover endpoints
            console.print("[cyan]🔍 Discovering API endpoints...[/cyan]")
            endpoints = await self._discover_endpoints(wordlists)
            
            # Step 3: Test endpoints for vulnerabilities
            console.print(f"[cyan]🧪 Testing {len(endpoints)} endpoints for vulnerabilities...[/cyan]")
            await self._test_endpoints(endpoints)
            
            # Step 4: Generate smart wordlist from discovered endpoints
            console.print("[cyan]🧠 Generating smart wordlist from patterns...[/cyan]")
            smart_endpoints = await self.endpoint_discovery.generate_smart_endpoints(
                self.discovered_endpoints, self.config.target_url
            )
            
            if smart_endpoints:
                console.print(f"[cyan]🎯 Testing {len(smart_endpoints)} smart-generated endpoints...[/cyan]")
                await self._test_endpoints(smart_endpoints)
        
        scan_duration = time.time() - start_time
        console.print(f"\n[green]⏱️  Scan completed in {scan_duration:.2f} seconds[/green]")
        console.print(f"[cyan]📊 Total results collected: {len(self.results)}[/cyan]")
        
        return self.results
    
    async def _discover_endpoints(self, wordlists: List[str]) -> List[Tuple[str, str]]:
        """Discover API endpoints using wordlists."""
        endpoints = []
        methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]
        
        # Generate endpoint URLs
        for word in wordlists:
            for method in methods:
                endpoint_url = urljoin(self.config.target_url.rstrip('/') + '/', word.strip())
                endpoints.append((endpoint_url, method))
        
        return endpoints
    
    async def _test_endpoints(self, endpoints: List[Tuple[str, str]]):
        """Test endpoints for existence and vulnerabilities."""
        semaphore = asyncio.Semaphore(self.config.threads)
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            
            task = progress.add_task("Testing endpoints...", total=len(endpoints))
            
            async def test_single_endpoint(endpoint_data: Tuple[str, str]):
                async with semaphore:
                    url, method = endpoint_data
                    # console.print(f"[DEBUG] Testing in wrapper: {method} {url}", style="dim yellow")
                    await asyncio.sleep(self.config.delay)
                    
                    result_from_test: Optional[ScanResult] = None
                    try:
                        result_from_test = await self._test_single_endpoint(url, method)
                        if result_from_test:
                            self.results.append(result_from_test)
                            logger.debug(f"Added result for {url}: {result_from_test.status_code}")
                            # console.print(f"[DEBUG] Appended result for {url} with status {result_from_test.status_code}", style="dim green")
                            if result_from_test.status_code < 400:
                                self.discovered_endpoints.add(url)
                        else:
                            # console.print(f"[DEBUG] No result returned for {method} {url}", style="dim red")
                            pass # Explicitly pass if no result, to avoid unused var warning if not logging
                                
                    except Exception as e:
                        # console.print(f"[DEBUG] EXCEPTION in wrapper for {method} {url}: {type(e).__name__} - {str(e)}", style="bold red")
                        logger.debug(f"Error testing {url}: {str(e)}", exc_info=self.config.verbose)
                    finally:
                        progress.advance(task)
            
            # Execute all tests concurrently
            await asyncio.gather(*[test_single_endpoint(ep) for ep in endpoints])
    
    async def _test_single_endpoint(self, url: str, method: str) -> Optional[ScanResult]:
        """Test a single endpoint."""
        # console.print(f"[DEBUG] Attempting: {method} {url}", style="dim cyan")
        start_time = time.time()
        
        try:
            if self.client is None:
                # console.print(f"[DEBUG] CRITICAL: self.client is None before request for {method} {url}", style="bold red")
                return None

            response = await self.client.request(method, url)
            # console.print(f"[DEBUG] Response for {method} {url}: Status {response.status_code}", style="dim blue")
            
            response_time = time.time() - start_time
            
            # Test for vulnerabilities (even on 404s, some might be interesting)
            vulnerabilities = await self.vuln_tester.test_endpoint(
                self.client, url, method, response
            )
            
            # Determine severity
            severity = self._calculate_severity(vulnerabilities)
            
            result = ScanResult(
                endpoint=url,
                method=method,
                status_code=response.status_code,
                response_time=response_time,
                content_length=len(response.content),
                vulnerabilities=vulnerabilities,
                headers=dict(response.headers),
                timestamp=datetime.now().isoformat(),
                severity=severity
            )
            # console.print(f"[DEBUG] Formed result for {method} {url}: Status {result.status_code}", style="dim green")
            
            # Log interesting findings
            if response.status_code < 400:
                logger.info(f"Found endpoint: {method} {url} [{response.status_code}]")
                console.print(f"[green]✓[/green] Found: {method} {url} [{response.status_code}]")
            elif response.status_code != 404:
                logger.info(f"Interesting response: {method} {url} [{response.status_code}]")
                console.print(f"[yellow]![/yellow] Interesting: {method} {url} [{response.status_code}]")
                
            if vulnerabilities:
                logger.warning(f"Vulnerabilities found in {url}: {len(vulnerabilities)}")
                console.print(f"[red]🚨[/red] Vulnerabilities in {url}: {len(vulnerabilities)}")
            
            # Return result for all responses (not just successful ones)
            return result
            
        except httpx.TimeoutException:
            # console.print(f"[DEBUG] TIMEOUT for {method} {url}", style="bold red")
            logger.debug(f"Timeout for {method} {url}")
            return None
        except Exception as e:
            # console.print(f"[DEBUG] EXCEPTION in _test_single_endpoint for {method} {url}: {type(e).__name__} - {str(e)}", style="bold red")
            logger.debug(f"Error testing {method} {url}: {str(e)}", exc_info=self.config.verbose)
            return None
    
    def _calculate_severity(self, vulnerabilities: List[Dict]) -> str:
        """Calculate overall severity for an endpoint."""
        if not vulnerabilities:
            return "info"
        
        severities = [vuln.get("severity", "low") for vuln in vulnerabilities]
        
        if "critical" in severities:
            return "critical"
        elif "high" in severities:
            return "high"
        elif "medium" in severities:
            return "medium"
        else:
            return "low"
    
    def display_summary(self, results: List[ScanResult]):
        """Display scan summary in a beautiful table."""
        # Calculate statistics
        total_endpoints = len(results)
        endpoints_found = len([r for r in results if r.status_code < 400])
        endpoints_interesting = len([r for r in results if 400 <= r.status_code < 500 and r.status_code != 404])
        total_vulns = sum(len(r.vulnerabilities) for r in results)
        
        high_severity = len([r for r in results if r.severity in ["critical", "high"]])
        medium_severity = len([r for r in results if r.severity == "medium"])
        low_severity = len([r for r in results if r.severity == "low"])
        
        # Create summary table
        table = Table(title="🎯 APIVulnMiner Scan Summary", show_header=True, header_style="bold magenta")
        table.add_column("Metric", style="cyan", no_wrap=True)
        table.add_column("Value", style="green")
        
        table.add_row("Target URL", self.config.target_url)
        table.add_row("Total Endpoints Tested", str(total_endpoints))
        table.add_row("✅ Endpoints Found (2xx-3xx)", str(endpoints_found))
        table.add_row("⚠️  Interesting Responses (4xx-5xx)", str(endpoints_interesting))
        table.add_row("Total Vulnerabilities", str(total_vulns))
        table.add_row("🔴 High/Critical Severity", str(high_severity))
        table.add_row("🟡 Medium Severity", str(medium_severity))
        table.add_row("🟢 Low Severity", str(low_severity))
        
        console.print("\n")
        console.print(table)
        
        # Show detailed results if any endpoints found
        if endpoints_found > 0 or endpoints_interesting > 0:
            self._display_detailed_results(results)
        
        # Show top vulnerabilities
        if total_vulns > 0:
            self._display_top_vulnerabilities(results)
    
    def _display_detailed_results(self, results: List[ScanResult]):
        """Display detailed results of found endpoints."""
        # Filter for interesting results
        interesting_results = [r for r in results if r.status_code < 500 and r.status_code != 404]
        
        if not interesting_results:
            return
            
        results_table = Table(title="📋 Detailed Scan Results", show_header=True, header_style="bold blue")
        results_table.add_column("Method", style="cyan", width=8)
        results_table.add_column("Endpoint", style="white", width=40)
        results_table.add_column("Status", style="green", width=8)
        results_table.add_column("Size", style="yellow", width=8)
        results_table.add_column("Time", style="magenta", width=8)
        results_table.add_column("Vulns", style="red", width=6)
        
        # Sort by status code and then by endpoint
        interesting_results.sort(key=lambda x: (x.status_code, x.endpoint))
        
        for result in interesting_results[:50]:  # Show top 50 results
            status_color = "green" if result.status_code < 400 else "yellow"
            endpoint_short = result.endpoint.replace(self.config.target_url, "")
            if len(endpoint_short) > 35:
                endpoint_short = endpoint_short[:32] + "..."
                
            results_table.add_row(
                result.method,
                endpoint_short,
                f"[{status_color}]{result.status_code}[/{status_color}]",
                f"{result.content_length}B",
                f"{result.response_time:.2f}s",
                str(len(result.vulnerabilities))
            )
        
        console.print("\n")
        console.print(results_table)
    
    def _display_top_vulnerabilities(self, results: List[ScanResult]):
        """Display top vulnerabilities found."""
        vuln_table = Table(title="🚨 Top Vulnerabilities Found", show_header=True, header_style="bold red")
        vuln_table.add_column("Endpoint", style="cyan")
        vuln_table.add_column("Vulnerability", style="yellow")
        vuln_table.add_column("Severity", style="red")
        vuln_table.add_column("Description", style="white")
        
        # Get top 10 vulnerabilities
        all_vulns = []
        for result in results:
            for vuln in result.vulnerabilities:
                all_vulns.append((result.endpoint, vuln))
        
        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        all_vulns.sort(key=lambda x: severity_order.get(x[1].get("severity", "low"), 3))
        
        for endpoint, vuln in all_vulns[:10]:
            severity_color = {
                "critical": "bright_red",
                "high": "red",
                "medium": "yellow",
                "low": "green"
            }.get(vuln.get("severity", "low"), "white")
            
            vuln_table.add_row(
                endpoint.replace(self.config.target_url, ""),
                vuln.get("name", "Unknown"),
                f"[{severity_color}]{vuln.get('severity', 'low').upper()}[/{severity_color}]",
                vuln.get("description", "No description")[:50] + "..."
            )
        
        console.print("\n")
        console.print(vuln_table)
    
    async def generate_report(self, results: List[ScanResult], format_type: str, output_file: str):
        """Generate scan report in specified format."""
        from .reporting import ReportGenerator
        
        generator = ReportGenerator()
        await generator.generate_report(results, format_type, output_file, self.config) 