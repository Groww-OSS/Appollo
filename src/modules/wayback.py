import subprocess
import asyncio
import re
from rich import print

"""
This module provides a class GAU to interact with the `gau` command-line tool for fetching URLs from various sources.
Classes:
    GAU: A class to handle the execution of the `gau` command and process its output.
Methods:
    __init__(): Initializes the GAU class and checks if the `gau` command is available.
    get_gau(target_url): Asynchronously runs the `gau` command for a given target URL and stores the results.
    run(target_urls): Asynchronously runs the `gau` command for a list of target URLs and returns the results.
Exceptions:
    SystemExit: Raised when the `gau` command is not found or encounters an issue.
"""

DOMAIN_PATTERN = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$')
SUBPROCESS_TIMEOUT = 300


class GAU:
    def __init__(self):
        try:
            subprocess.run(['gau', '--help'], capture_output=True, check=True)
            self.domains = {}
        except FileNotFoundError:
            print("[bold red]Error: gau command not found. Please install gau.[/bold red]")
            raise SystemExit(1)
        except subprocess.CalledProcessError:
            print("[bold red]Error: gau command is installed but encountered an issue.[/bold red]")
            raise SystemExit(1)
        
    async def get_gau(self, target_url):
        if not DOMAIN_PATTERN.match(target_url):
            print(f"[bold yellow][-] Skipping invalid target: {target_url}[/bold yellow]")
            return self.domains

        if target_url not in self.domains:
            self.domains[target_url] = []

        try:
            command = ['gau', '--', target_url]
            result = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                result.communicate(), timeout=SUBPROCESS_TIMEOUT
            )
        except asyncio.TimeoutError:
            print(f"[bold yellow][-] {target_url}: timed out after {SUBPROCESS_TIMEOUT}s[/bold yellow]")
            try:
                result.kill()
            except ProcessLookupError:
                pass
            return self.domains
        except Exception as e:
            print(f"[bold red][-] {target_url}: unexpected error - {e}[/bold red]")
            return self.domains

        self._completed += 1

        if result.returncode == 0:
            output = stdout.strip().decode().split('\n')
            cleaned = [url.strip() for url in output if url.strip()]
            self.domains[target_url].extend(cleaned)
            print(f"[bold green][+] [{self._completed}/{self._total}] {target_url}: Found {len(cleaned)} URLs[/bold green]")
        else:
            print(f"[bold red][-] [{self._completed}/{self._total}] {target_url}: Error - {stderr.decode().strip()}[/bold red]")

        return self.domains
    
    async def run(self, target_urls):
        target_urls = list(set(target_urls))
        self._total = len(target_urls)
        self._completed = 0
        print(f"[bold blue][+] Starting wayback scan for {self._total} domains[/bold blue]")

        try:
            await asyncio.gather(*[self.get_gau(target_url) for target_url in target_urls])
        except asyncio.CancelledError:
            print("[bold yellow]Wayback scan cancelled.[/bold yellow]")
        except Exception as e:
            print(f"[bold red][-] Wayback scan error: {e}[/bold red]")

        total_urls = sum(len(urls) for urls in self.domains.values())
        print(f"[bold green][+] Wayback scan finished: {total_urls} total URLs across {self._total} domains[/bold green]")
        return self.domains
