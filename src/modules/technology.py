import re
import traceback
import requests
import os

"""
This module provides a class BuiltWithScanner to interact with the BuiltWith API for scanning
websites and detecting technologies used. When BUILTWITH_API_KEY is not set, a free fallback
detects technologies from HTTP headers and HTML (meta tags, script paths) so tech scan
still runs without a paid API.
"""

# Free detection: header and HTML patterns. (header_name, category) or (regex, category, display_name).
_HEADER_PATTERNS = [
    ("Server", "Web Server"),
    ("X-Powered-By", "Application"),
    ("X-Generator", "CMS"),
    ("X-AspNet-Version", "Application"),
    ("X-Drupal-Cache", "CMS"),
    ("X-Varnish", "Cache"),
    ("X-Cache", "Cache"),
]
_HTML_PATTERNS = [
    (re.compile(r'<meta\s+name=["\']generator["\']\s+content=["\']([^"\']+)["\']', re.I), "CMS", None),
    (re.compile(r'wp-content/|wp-includes/|wordpress', re.I), "CMS", "WordPress"),
    (re.compile(r'/react[\d.-]*\.js|react\.production', re.I), "JavaScript", "React"),
    (re.compile(r'/vue[\d.-]*\.js|vue\.min\.js', re.I), "JavaScript", "Vue.js"),
    (re.compile(r'angular[\d.-]*\.js|ng-version', re.I), "JavaScript", "Angular"),
    (re.compile(r'jquery[\d.-]*\.min\.js|jquery\.min\.js', re.I), "JavaScript", "jQuery"),
    (re.compile(r'bootstrap[\d.-]*\.(css|js)', re.I), "CSS Framework", "Bootstrap"),
    (re.compile(r'next\.js|__NEXT_DATA__', re.I), "JavaScript", "Next.js"),
    (re.compile(r'nuxt|__NUXT__', re.I), "JavaScript", "Nuxt"),
]


def _tech_entry(name, description="", version=None, tag=None):
    """Build a tech dict compatible with BuiltWith-style storage."""
    tag = tag or name.replace(" ", "")
    return {
        "name": name,
        "description": description,
        "version": version,
        "tag": tag,
        "FirstDetected": "",
        "LastDetected": "",
        "website": None,
    }


def _free_detect(url, session=None):
    """
    Detect technologies from one URL using headers and HTML only (no paid API).
    Returns dict: category -> list of tech entries. Empty dict on error.
    """
    if session is None:
        session = requests.Session()
    categories = {}
    try:
        if "://" not in url:
            processed_url = f"https://{url}"
        else:
            processed_url = url
        resp = session.get(
            processed_url,
            timeout=15,
            headers={"User-Agent": "Mozilla/5.0 (compatible; AppolloTechScan/1.0)"},
            allow_redirects=True,
        )
        resp.raise_for_status()
        text = resp.text or ""
        # From headers
        for header_name, category in _HEADER_PATTERNS:
            val = resp.headers.get(header_name)
            if val:
                val = val.strip().split("/")[0].strip()
                if val and len(val) < 200:
                    if category not in categories:
                        categories[category] = []
                    categories[category].append(_tech_entry(val, f"From {header_name} header", tag=val.replace(" ", "")))
        # From HTML
        for pattern, category, display_name in _HTML_PATTERNS:
            m = pattern.search(text)
            if m:
                name = (m.group(1) if m.groups() else display_name) or "Detected"
                if category not in categories:
                    categories[category] = []
                categories[category].append(_tech_entry(name, "From page content", tag=(name or "").replace(" ", "")[:50]))
        return categories
    except Exception as e:
        print(f"[-] Free tech detection failed for {url}: {e}")
        return {}


class BuiltWithScanner:
    def __init__(self, urls):
        self.urls = urls

    def scan(self):
        """Returns (data, source): data is domain -> categories dict, source is 'BuiltWith' or 'FreeDetector'."""
        data = {}
        try:
            api_key = os.environ.get('BUILTWITH_API_KEY')
            if not api_key:
                print("[*] BUILTWITH_API_KEY not set; using free technology detection (headers + HTML)")
                session = requests.Session()
                for url in self.urls:
                    norm_url = url.replace("https://", "").replace("http://", "")
                    categories = _free_detect(url, session=session)
                    if categories:
                        data[norm_url] = categories
                return (data, "FreeDetector")
            for url in self.urls:
                if "://" not in url:
                    processed_url = f"https://{url}"
                else:
                    processed_url = url
                
                response = requests.get(
                    "https://api.builtwith.com/v21/api.json",
                    params={"KEY": api_key, "LOOKUP": processed_url},
                    timeout=30
                )
                if response.status_code != 200:
                    print(f"[-] BuiltWith API returned {response.status_code} for {url}")
                    continue
                response_data = response.json()
                if not response_data.get("Results"):
                    print(f"[-] No technology found for {url} with BuiltWith")
                    continue
                else:
                    categories = {}
                    for tech in response_data["Results"][0]["Result"]["Paths"]:
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
            return (data, "BuiltWith")
        except Exception as e:
            print("[-] Error in BuiltWithScanner: ", e)
            print(traceback.format_exc())
            return (data, "BuiltWith")   
        
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