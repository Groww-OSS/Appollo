import json
import subprocess

"""
This module provides functionality to perform a port scan on a given host using the naabu command.

Classes:
    PortScan: A class to handle the execution of the naabu command and parse its output.

Methods:
    run(host, flags): Executes the naabu command with the specified host and flags, parses the JSON output, and returns a list of open ports.
"""

NAABU_TIMEOUT = 600


class PortScan:

    def run(self, host: str, flags: str) -> list:
        command = ["naabu", "-host", host] + flags.split() + ["-json"]

        try:
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output, _ = process.communicate(timeout=NAABU_TIMEOUT)
            lines = output.decode("utf-8").splitlines()
            seen = set()
            ports = []
            for line in lines:
                line = line.strip()
                if line and not line.startswith("[INF]"):
                    try:
                        port = json.loads(line).get("port")
                        if port and port not in seen:
                            seen.add(port)
                            ports.append(port)
                    except json.JSONDecodeError:
                        continue
            return ports
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
            print(f"[-] naabu timed out for {host} after {NAABU_TIMEOUT}s")
            return []
        except Exception as e:
            print(f"[-] Error running naabu: {e}")
            return []
