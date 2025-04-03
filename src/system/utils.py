import hashlib, requests, os, json
from tinydb import TinyDB, Query
import pandas as pd
import csv
from jira import JIRA

def get_jira_client():
    options = {
        'server': os.environ.get("JIRA_SERVER"),
    }
    return JIRA(options, basic_auth=(os.environ.get("JIRA_USER"), os.environ.get("JIRA_API_TOKEN")))

def create_jira_issue(jira_client, project_key, summary, description, issue_type="Bug", label="periodic-scan"):
    issue_dict = {
        'project': {'key': project_key},
        'summary': summary,
        'description': description,
        'issuetype': {'name': issue_type},
        'priority': {'name': 'High'},
        'labels': [label],
    }
    return jira_client.create_issue(fields=issue_dict)

def is_private_ip(ip):
    if((ip.startswith("192.168"))and ip.startswith("172.") and ip.startswith("127.")and ip.startswith("10.")):
        return True


def calculate_hash(data):
    json_data = None

    if isinstance(data, pd.DataFrame):
         
        json_data = data.to_json(orient='records', default_handler=str)
    elif isinstance(data, (dict, list)):
         
        json_data = json.dumps(data, default=str, sort_keys=True)
    elif isinstance(data, str):
        
        json_data = data
    else:
        print(f"Unsupported data type: {type(data)}")
        raise ValueError("Unsupported data type for hashing")

    if json_data is not None:
        return hashlib.sha256(json_data.encode()).hexdigest()

def upload_file_to_slack(file_path, initial_comment):
    command = f'curl -F file=@{file_path} -F initial_comment="{initial_comment}" -F channels={os.environ["CHANNEL_ID"]} -H "Authorization: Bearer {os.environ["SLACK_API_KEY"]}" https://slack.com/api/files.upload  > /dev/null 2>&1'
    os.system(command)

def send_slack_alert(msg):
    url = os.environ.get("WEBHOOK_URL")
    if not url:
        print("WEBHOOK_URL not set")
        return
    data = {"text": msg}
    requests.post(url, json=data)

def save_wayback_to_csv(new_data, file_path):
    if os.path.exists(file_path) and os.path.getsize(file_path) > 0:
        df_existing = pd.read_csv(file_path)
    else:
        df_existing = pd.DataFrame(columns=["Domain", "URL"])
    
    data = []
    for domain, links in new_data.items():
        for link in links:
            data.append([domain, link])
    
    df_new = pd.DataFrame(data, columns=["Domain", "URL"])
    
    df_combined = pd.concat([df_existing, df_new], ignore_index=True).drop_duplicates()
    
    df_combined.to_csv(file_path, index=False)


def save_port_scan_to_csv(new_data, file_path):
    """Append new Port Scan data to an existing CSV file using pandas."""
    if os.path.exists(file_path) and os.path.getsize(file_path) > 0:
        df_existing = pd.read_csv(file_path)
    else:
        df_existing = pd.DataFrame(columns=["Domain", "IP", "Port"])
    data = []
    for domain, info in new_data.items():
        ip = info['ip']
        for port in info['ports']:
            data.append([domain, ip, port])
    
    df_new = pd.DataFrame(data, columns=["Domain", "IP", "Port"])
    df_combined = pd.concat([df_existing, df_new], ignore_index=True).drop_duplicates()
    df_combined.to_csv(file_path, index=False)


def read_from_csv(file_path):
    """Read  results from a CSV file using pandas."""
    if os.path.exists(file_path) and os.path.getsize(file_path) > 0:
        df = pd.read_csv(file_path)
        if not df.empty:
            if 'Port' in df.columns:
                data = df.groupby('Domain')['Port'].apply(list).to_dict()
            else:
                data = df.groupby('Domain')['URL'].apply(list).to_dict()
            return data
    return {}


def get_delta_links(current_results, previous_results):
    """Find new URLs by comparing current results with previous ones."""
    new_links = {}
    for domain, links in current_results.items():
        prev_links = previous_results.get(domain, [])
        new_for_domain = list(set(links) - set(prev_links))  
        if new_for_domain:
            new_links[domain] = new_for_domain
    return new_links

def convert_to_csv(data, output_file):
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['URL', 'Name' ,'Vulnerability', 'Exploit URL', 'Description', 'Request'])
        for url, details in data.items():
            for item in details:
                writer.writerow([url] + item)

def get_delta_ports(current_results, previous_results):
    """Find new ports by comparing current results with previous ones."""
    new_ports = {}
    for domain, data in current_results.items():
        current_ports = data['ports']
        prev_ports = previous_results.get(domain, [])

        delta_ports = list(set(current_ports) - set(prev_ports))
        delta_ports.sort()   
        
        if delta_ports:   
            new_ports[domain] = {
                'ip': data['ip'],
                'ports': delta_ports
            }
    return new_ports


def write_file(file_path, content):
    with open(file_path, "w") as f:
        f.write(content)

def read_file(file_path):
    with open(file_path, "r", encoding="utf-8") as f:
        return f.read()

def is_file_exists(file_path):
    return os.path.exists(file_path)

def check_if_hash_exists(hash):
    db = TinyDB("/etc/config/db.json")
    query = Query()
    result = db.search(query.hash == hash)
    if result:
        return True
    else:
        return False

def add_hash_to_db(hash):
    db = TinyDB("/etc/config/db.json")
    db.insert({"hash": hash})

def find_new_urls(string1, string2):
    if string1 == "":
        string1 = "{}"
    data1 = eval(string1)
    data2 = eval(string2)
    

    all_urls1 = set()
    all_urls2 = set()

    for key, value in data1.items():
        all_urls1.update(value)

    for key, value in data2.items():
        all_urls2.update(value)

    new_urls = all_urls2 - all_urls1
    new_data = {key: list(new_urls)}
    new_data_string = json.dumps(new_data)

    return new_data_string