import traceback
import requests
import json
import os

"""
This module provides a class BuiltWithScanner to interact with the BuiltWith API for scanning websites and detecting technologies used.

Classes:
    BuiltWithScanner: A class to handle the scanning of websites using the BuiltWith API.
Methods:
    __init__(urls): Initializes the BuiltWithScanner class with a list of URLs to scan.
    scan(): Scans the provided URLs and returns a dictionary with detected technologies categorized.
    extract_version(name, description): Extracts the version of a technology from its name or description.
Exceptions:
    Exception: Raised when there is an error during the scanning process.
"""


class BuiltWithScanner:
    def __init__(self, urls):
        self.urls = urls

    def scan(self):
        data = {}
        try:
            for url in self.urls:
                if not url.startswith("http") or not url.startswith("https"):
                    url = f"https://{url}"
                response = requests.get(f"https://api.builtwith.com/v21/api.json?KEY={os.environ['BUILTWITH_API_KEY']}&LOOKUP={url}")
                if response.status_code == 200:
                    response = response.json()
                if response["Results"]:
                    categories = {}
                    for tech in response["Results"][0]["Result"]["Paths"]:
                        if "Technologies" in tech:
                            for category in tech["Technologies"]:
                                if "Categories" in category and category["Categories"]:
                                    for cat in category["Categories"]:
                                        technology = {
                                            "name": category["Name"],
                                            "description": category["Description"],
                                            "version": extract_version(category["Name"], category["Description"]),
                                            "tag": category["Tag"],
                                            "FirstDetected": category["FirstDetected"],
                                            "LastDetected": category["LastDetected"],
                                            "website": category.get("Link"),
                                        }
                                        if cat not in categories:
                                            categories[cat] = [technology]
                                        else:
                                            categories[cat].append(technology)
                                else:
                                    technology = {
                                        "name": category["Name"],
                                        "description": category["Description"],
                                        "version": extract_version(category["Name"], category["Description"]),
                                        "tag": category["Tag"],
                                        "FirstDetected": category["FirstDetected"],
                                        "LastDetected": category["LastDetected"],
                                        "website": category.get("Link"),
                                    }
                                    if category["Tag"] not in categories:
                                        categories[category["Tag"]] = [technology]
                                    else:
                                        categories[category["Tag"]].append(technology)
                    url = url.replace("https://", "").replace("http://", "")
                    data[url] = categories
                else:
                    print(f"[-] No technology found for {url} with BuiltWith")
                    pass
            return data
        except Exception as e:
            print("[-] Error in BuiltWithScanner: ", e)
            print(traceback.format_exc())
        
def extract_version(name, description):
    version = None
    name_parts = name.split(" ")
    if len(name_parts) > 1:
        last_part = name_parts[-1]
        if last_part.replace(".", "").isdigit() and not last_part.isdigit():
            version = last_part
    if not version:
        description_parts = description.split(" ")
        for index, part in enumerate(description_parts):
            if part.lower() == "version" and index < len(description_parts) - 1:
                next_part = description_parts[index + 1]
                if next_part.replace(".", "", 1).isdigit() or next_part.endswith(".*"):
                    version = next_part
                    break
    return version