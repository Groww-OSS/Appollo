<br/>
<div align="center">
<a href="https://github.com/ShaanCoding/ReadME-Generator">
<img src="https://resources.groww.in/web-assets/img/website-logo/groww-logo-dark.svg" alt="Logo" width="180" height="90">
</a>
<h1 align="center">Appollo - C.A.S.T. solution</h1>
<p align="center">Think you're secure? Appollo will make sure.
<br/>
 <a href="/src/poc/Appollo-Poc.mp4">View Demo</a>  
 <a href="mailto:security@groww.in">Report Bug</a>
 <a href="./CONTRIBUTE.md">Request Feature</a>
</p>
</div>

## About The Project
![Modules](/src/images/HLD.png)

**Appollo** is a security tool designed to continuously assess and monitor the attack surface of an organization's digital infrastructure. It systematically identifies, analyzes, and reports on potential vulnerabilities and weaknesses in networks, applications, and systems. By providing ongoing visibility into security risks, Appollo enables organizations to proactively address issues, strengthen their defenses, and reduce the likelihood of successful cyber attacks.

Here's why:
- **Internal Asset Access:** Utilizes internal assets effectively to accelerate scans, allowing rapid detection of vulnerabilities.
- **Scalability:** Adapts to organizational growth and infrastructure changes.
- **DNS and Subdomain Monitoring:** Tracks DNS records and subdomains, alerting on changes.
- **SSL Validation Monitoring:** Monitors SSL certificate expiry for domains.
- **IP Discovery:** Maintains a comprehensive list of all IP addresses.
- **Port Scanning:** Identify critical open ports.
- **Endpoint Checking:** Monitors common exposed directory endpoints for security risks.
- **Historical Data Analysis:** Leverages wayback and common crawl for insights into past data.
- **Technology Stack Scanning:** Detects and assesses technology stacks for vulnerabilities.
- **CVE-Based Vulnerability Scanning:** Identifies and reports known vulnerabilities using CVE databases.
- **Dangling DNS Scan:** Identify DNS records pointing to unclaimed or decommissioned resources that could be hijacked for subdomain takeover.
- **Slack & Jira** – Streamline alerts and ticketing for faster action.
- **Intuitive Dashboard** – A user-friendly UI for better asset tracking and security gap analysis.

## Architecture
![Architecture](/src/images/architecture.png)

## Getting Started
To get a local copy up and running follow these simple example steps.

### Prerequisites
- nuclei
  ```console
  go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
  ```
- gau
  ```console
  go install github.com/lc/gau/v2/cmd/gau@latest
  ```
- tlsx
  ```console
  go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest
  ```
- naabu
  ```console
  go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@v2.3.3
  ```
- ffuf
  ```console
  go install github.com/ffuf/ffuf/v2@latest
  ```
- BuiltWithAPI
  * Get the api key from [BuiltWithApi](https://api.builtwith.com/free-api)

- gcloud

  * Refer this [link](https://cloud.google.com/sdk/docs/install) for installation.
  

### Installation
1. Clone the repo
   ```console
   git clone https://github.com/Groww-oss/Appollo.git
   ```
2. Install requirements
   ```console
   pip install -r requirements.txt
   ```
3. Enter your API Keys as well as required URLs in `.env`
   ```console
    CLOUDFLARE_API_KEY=<API_KEY>
    MONGO_URI=<MONGO_URI>
    MONGI_DB=<MONGO_DB>
    WEBHOOK_SERVER_PORT= 5002
    WEBHOOK_URL=<SLACK_WEBHOOK_URL>
    SLACK_API_KEY=<SLACK_BOT_TOKEN>
    CHANNEL_ID=<SLACK_CHANNEL_ID>
    JIRA_SERVER=<JIRA_SERVER_URL>
    JIRA_USER=<JIRA_USER>
    JIRA_API_TOKEN=<JIRA_API_TOKEN>
    JIRA_BOARD_NAME=<JIRA_BOARD_NAME>
    SVC_ACCOUNT=<SERVICE_ACCOUNT_FILE_PATH>
    DIRECTORY_WORDLIST=<DIRECTORY_FUZZING_WORDLIST>
    NUCLEI_TEMPLATE=<NUCLEI_TEMPLATE_PATH>
   ```

## Usage
To use Appollo, you can run the following commands based on your requirements:
```console
usage: appollo.py [-h] -e ENV [-t TARGET] [-U] [-sc] [-ps] [-ws] [-fs] [-ts] [-ds] [-ns] [-dd] [-A]

Appollo - Reconnaissance Tool

options:
  -h, --help            show this help message and exit
  -e ENV, --env ENV     Path to the .env file
  -t TARGET, --target TARGET
                        Target domain, IP, CIDR, or any asset which is supported by Appollo
  -U, --update-inventory
                        Update Inventory Records
  -sc, --ssl-checker    Run SSL Checker
  -ps, --port-scan      Run port scan logic
  -ws, --wayback-scan   Run wayback scan logic
  -fs, --firewall-port-scan
                        Run port scan based on firewall rules
  -ts, --tech-scan      Run Technology scan
  -ds, --dir-scan       Run directory scan logic
  -ns, --nuclei-scan    Run nuclei scans for CVE's
  -dd, --dangling-dns   Run dangling DNS scan
  -A, --complete-scan   Run Complete scan for all known assets in inventory
```

## Video POC

https://github.com/user-attachments/assets/4997d3ef-6c49-46c6-a88f-e1c102ba5240

  

## Appollo Dashboard

Please refer to the following repository to set up the new Appollo dashboard locally.

- [Appollo Dashboard](https://github.com/Groww-OSS/Appollo-Dashboard)

## Latest Updates
- **Dangling DNS Scan:** New module to detect DNS records pointing to unclaimed or decommissioned resources, helping prevent subdomain takeover.
- **Firewall Rules–Based Port Scan:** Enhanced port scanning that respects and leverages firewall rules for more accurate exposure analysis.
- **Multi-Stage Docker Build:** Optimized Dockerfile using a multi-stage build for smaller, more secure, and faster-to-deploy images.

## How to contribute ?

We welcome contributions! Please check out our [CONTRIBUTE.md](./CONTRIBUTE.md) for detailed guidelines on how to get started.  


## License
Distributed under the MIT License. See [MIT License](/LICENSE) for more information.

## Contact
Bhavye Malhotra - [@wh1t3r0se_](https://twitter.com/wh1t3r0se_) - bhavyem@groww.in  
Srilakshmi Prathapan - [@L0xm1](https://twitter.com/L0xm1_07) - srilakshmip@groww.in


