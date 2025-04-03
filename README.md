<br/>
<div align="center">
<a href="https://github.com/ShaanCoding/ReadME-Generator">
<img src="https://resources.groww.in/web-assets/img/website-logo/groww-logo-dark.svg" alt="Logo" width="180" height="90">
</a>
<h1 align="center">Appollo - C.A.S.T. solution</h1>
<p align="center">Think you're secure? Appollo will make sure.
<br/>
<a href="https://youtube.com">View Demo</a>  
<a href="security@groww.in">Report Bug</a>
<a href="security@groww.in">Request Feature</a>
</p>
</div>

## About The Project
![Modules](https://i.imgur.com/hRLLDaJ.png)

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
- **Slack & Jira** – Streamline alerts and ticketing for faster action.
- **Intuitive Dashboard** – A user-friendly UI for better asset tracking and security gap analysis.

## Architecture
![Architecture](/src/images/architecture.png)

## Getting Started
To get a local copy up and running follow these simple example steps.

### Prerequisites
- nuclei
  ```sh
  go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
  ```
- gau
  ```sh
  go install github.com/lc/gau/v2/cmd/gau@latest
  ```
- tlsx
  ```sh
  go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest
  ```
- naabu
  ```sh
  go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@v2.3.3
  ```
- ffuf
  ```sh
  go install github.com/ffuf/ffuf/v2@latest
  ```
- BuiltWithAPI
  * Get the api key from [BuiltWithApi](https://api.builtwith.com/free-api)

- gcloud

  * Refer this [link](https://cloud.google.com/sdk/docs/install) for installation.
  

### Installation
1. Clone the repo
   ```sh
   git clone https://github.com/Groww-oss/Appollo.git
   ```
2. Install requirements
   ```sh
   pip install -r requirements.txt
   ```
3. Enter your API Keys as well as required URLs in `.env`
   ```py
    CLOUDFLARE_API_KEY=<API_KEY>
    MONGO_URI=<MONGO_URI>
    MONGI_DB=<MONGO_DB>
    WEBHOOK_SERVER_PORT= 5002
    WEBHOOK_URL=<SLACK_WEBHOOK_URL>
    BUILTWITH_API_KEY= <BUILTWITH_API_KEY>
    SLACK_API_KEY=<SLACK_BOT_TOKEN>
    CHANNEL_ID=<SLACK_CHANNEL_ID>
    JIRA_SERVER=<JIRA_SERVER_URL>
    JIRA_USER=<JIRA_USER>
    JIRA_API_TOKEN=<JIRA_API_TOKEN>
    SVC_ACCOUNT=<SERVICE_ACCOUNT_FILE_PATH>
    DIRECTORY_WORDLIST=<DIRECTORY_FUZZING_WORDLIST>
    NUCLEI_TEMPLATE=<NUCLEI_TEMPLATE_PATH>
   ```

## Usage
To use Appollo, you can run the following commands based on your requirements:
```
usage: appollo.py [-h] -e ENV [-t TARGET] [-U] [-sc] [-ps] [-ws]
                  [-ts] [-ds] [-ns] [-A]

Appollo - Reconnaissance Tool

options:
  -h, --help            show this help message and exit
  -e ENV, --env ENV     Path to the .env file
  -t TARGET, --target TARGET
                        Target domain, IP, CIDR, or any asset which
                        is supported by Appollo
  -U, --update-inventory
                        Update Inventory Records
  -sc, --ssl-checker    Run ssl Checker
  -ps, --port-scan      Run port scan logic
  -ws, --wayback-scan   Run wayback scan logic
  -ts, --tech-scan      Run technology scan
  -ds, --dir-scan       Run directory scan logic
  -ns, --nuclei-scan    Run nuclei scans for CVE's
  -A, --complete-scan   Run complete scan for all known assets in
                        inventory
```

## Video POC


https://github.com/user-attachments/assets/db07d141-a489-4947-a632-dfeef86b53f3



## Appsmith Dashboard
Follow these steps to set up your Appsmith dashboard using the provided .json file.

### Prerequisites
1. An Appsmith account.
  - Access to an Appsmith workspace ([cloud](https://app.appsmith.com/user/signup?_gl=1*1krl2cu*_gcl_au*MTgxMTYxMzk5NC4xNzM2MTQwMTMw*_ga*MTg5MDY1NTEzNC4xNzI3NDMyOTAz*_ga_D1VS24CQXE*MTczODA0NDI3MC4xMS4xLjE3MzgwNDU5ODIuMC4wLjA.) or [self-hosted](https://docs.appsmith.com/getting-started/setup?_gl=1*14lujaf*_gcl_au*MTgxMTYxMzk5NC4xNzM2MTQwMTMw*_ga*MTg5MDY1NTEzNC4xNzI3NDMyOTAz*_ga_D1VS24CQXE*MTczODA0NDI3MC4xMS4wLjE3ODA0NDI3MC4wLjA.)).
2. The .json file for the dashboard.

### Steps to Set Up
1. Log in to Appsmith
  * Go to Appsmith and log in or sign up.
2. Go to Your Workspace
  * Select an existing workspace or create a new one.
3. Import the Dashboard
  * Click New → Import Application.
  * Upload the provided [Appollo.json](/src/dashboard/Appollo.json) file under the dashboard directory in the repository.
4. Configure Datasources
  * Go to the Datasources tab.
  * Update MongoDB database credentials.

## Contributing
Contributions are what make the open source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**.

If you have a suggestion that would make this better, please fork the repo and create a pull request. You can also simply open an issue with the tag "enhancement".

Don't forget to give the project a star!

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/Feature`)
3. Commit your Changes (`git commit -m 'Add some Feature'`)
4. Push to the Branch (`git push origin feature/Feature`)
5. Open a Pull Request

## License
Distributed under the MIT License. See [MIT License](/LICENSE) for more information.

## Contact
Bhavye Malhotra - [@wh1t3r0se_](https://twitter.com/wh1tr0se_) - bhavyem@groww.in  
Srilakshmi Prathapan - [@L0xm1](https://twitter.com/L0xm1_07) - srilakshmip@groww.in

## Acknowledgments
- [Appsmith](https://github.com/appsmithorg/appsmith)
