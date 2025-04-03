import subprocess
import asyncio

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

class GAU:
    def __init__(self):
        try:
            subprocess.run(['gau', '--help'], capture_output=True, check=True)
            self.domains = {}
        except FileNotFoundError:
            print("Error: gau command not found. Please install gau.")
            raise SystemExit(1)
        except subprocess.CalledProcessError:
            print("Error: gau command is installed but encountered an issue.")
            raise SystemExit(1)
        
    async def get_gau(self, target_url):
        self.domains[target_url] = []
        command = ['gau', target_url]
        result = await asyncio.create_subprocess_exec(*command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        stdout, stderr = await result.communicate()
        if result.returncode == 0:
            output = stdout.strip().decode().split('\n')
            self.domains[target_url].extend(output)
        else:
            print(f"Error: {stderr.decode()}")
        return self.domains
    
    async def run(self, target_urls):
        try:
            await asyncio.gather(*[self.get_gau(target_url) for target_url in target_urls])
            return self.domains
        except KeyboardInterrupt:
            print("Error: Keyboard Interrupt")
            raise SystemExit(1)
        except FileNotFoundError:
            print("Error: gau command not found. Make sure it is installed and accessible.")
            return self.domains
        except subprocess.CalledProcessError as e:
            print(f"Error: gau command encountered an issue - {e}")
            return self.domains




