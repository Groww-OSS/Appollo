import json
import subprocess

"""
This module provides functionality to perform a port scan on a given host using the naabu command.

Classes:
    PortScan: A class to handle the execution of the naabu command and parse its output.

Methods:
    run(host, flags): Executes the naabu command with the specified host and flags, parses the JSON output, and returns a list of open ports.

Exceptions:
    json.JSONDecodeError: Raised when there is an error decoding the JSON output from the naabu command.
    subprocess.SubprocessError: Raised when there is an error during the execution of the naabu command.
"""

class PortScan:

    def run(self, host, flags):
        command = "naabu -host {host} {flags} -json".format(host=host, flags=flags)
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        output, _ = process.communicate()
        output = output.decode("utf-8").split("\n")
        ports = []
        for line in output:
            if line and not line.startswith("[INF]"):
                jsoned_line = json.loads(line)
                if jsoned_line["port"] not in ports:
                    ports.append(jsoned_line["port"])

        return ports