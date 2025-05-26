"""
Banner utility module
Displays cool ASCII art banner for the tool
"""

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.align import Align

console = Console()

def show_banner():
    """Display the APIVulnMiner banner."""
    
    banner_text = """
    ╔═══════════════════════════════════════════════════════════════╗
    ║                                                               ║
    ║     █████╗ ██████╗ ██╗██╗   ██╗██╗   ██╗██╗     ███╗   ██╗    ║
    ║    ██╔══██╗██╔══██╗██║██║   ██║██║   ██║██║     ████╗  ██║    ║
    ║    ███████║██████╔╝██║██║   ██║██║   ██║██║     ██╔██╗ ██║    ║
    ║    ██╔══██║██╔═══╝ ██║╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║    ║
    ║    ██║  ██║██║     ██║ ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║    ║
    ║    ╚═╝  ╚═╝╚═╝     ╚═╝  ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝    ║
    ║                                                               ║
    ║          ███╗   ███╗██╗███╗   ██╗███████╗██████╗              ║
    ║          ████╗ ████║██║████╗  ██║██╔════╝██╔══██╗             ║
    ║          ██╔████╔██║██║██╔██╗ ██║█████╗  ██████╔╝             ║
    ║          ██║╚██╔╝██║██║██║╚██╗██║██╔══╝  ██╔══██╗             ║
    ║          ██║ ╚═╝ ██║██║██║ ╚████║███████╗██║  ██║             ║
    ║          ╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝             ║
    ║                                                               ║
    ╚═══════════════════════════════════════════════════════════════╝
    """
    
    # Create styled banner
    banner = Text(banner_text, style="bold cyan")
    
    # Add subtitle
    subtitle = Text("Advanced API Vulnerability Scanner", style="bold white")
    subtitle_2 = Text("Automated Endpoint Discovery & Security Testing", style="italic bright_blue")
    
    # Version and author info
    version_info = Text("v1.0.0 | Created by Shan (@shaniidev)", style="dim white")
    author_info = Text("LinkedIn: linkedin.com/in/shaniii | GitHub: github.com/shaniidev", style="dim cyan")
    
    # Combine all text
    full_banner = Text()
    full_banner.append(banner)
    full_banner.append("\n")
    full_banner.append(subtitle)
    full_banner.append("\n")
    full_banner.append(subtitle_2)
    full_banner.append("\n\n")
    full_banner.append(version_info)
    full_banner.append("\n")
    full_banner.append(author_info)
    
    # Create panel
    panel = Panel(
        Align.center(full_banner),
        border_style="bright_magenta",
        padding=(1, 2)
    )
    
    console.print(panel)
    console.print()

def show_scan_start(target_url: str, threads: int, wordlist_size: int):
    """Display scan start information."""
    
    start_info = f"""
🎯 Target URL: {target_url}
🧵 Threads: {threads}
📝 Wordlist Size: {wordlist_size} endpoints
🔍 Starting comprehensive API security scan...
    """
    
    panel = Panel(
        start_info.strip(),
        title="[bold green]Scan Configuration[/bold green]",
        border_style="green",
        padding=(1, 2)
    )
    
    console.print(panel)
    console.print()

def show_scan_complete(total_endpoints: int, vulnerabilities: int, duration: str):
    """Display scan completion summary."""
    
    complete_info = f"""
✅ Scan completed successfully!

📊 Results Summary:
   • Total endpoints tested: {total_endpoints}
   • Vulnerabilities found: {vulnerabilities}
   • Scan duration: {duration}

📋 Check the generated report for detailed findings.
    """
    
    panel = Panel(
        complete_info.strip(),
        title="[bold green]Scan Complete[/bold green]",
        border_style="green",
        padding=(1, 2)
    )
    
    console.print(panel)

def show_error(message: str):
    """Display error message."""
    
    panel = Panel(
        f"❌ {message}",
        title="[bold red]Error[/bold red]",
        border_style="red",
        padding=(1, 2)
    )
    
    console.print(panel)

def show_warning(message: str):
    """Display warning message."""
    
    panel = Panel(
        f"⚠️  {message}",
        title="[bold yellow]Warning[/bold yellow]",
        border_style="yellow",
        padding=(1, 2)
    )
    
    console.print(panel) 