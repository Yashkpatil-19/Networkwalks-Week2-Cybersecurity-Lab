# Networkwalks-Week2-Cybersecurity-Lab

## Module 1 - Footprinting & Reconnaissance

**Objective:** Perform footprinting and reconnaissance on a target domain using multiple Kali Linux tools.

**Target:** `networkwalks.com` (the domain specified for this lab).
**Scope:** Only passive lookups and light, non-intrusive queries (for example, WAF detection used just 2 HTTP requests). No exploitation or intrusive testing was performed.

### Summary of findings

| Area | Finding |
|---|---|
| Registrar | GoDaddy.com, LLC - registrant hidden behind a WHOIS privacy proxy |
| Hosting | Name servers and IP point to HostGator; web IP `192.232.216.135` |
| Web server | Apache, HTTP -> HTTPS redirect (301) |
| CMS | WordPress 7.1.4 with WordPress Download Manager 3.3.76 |
| WAF | ModSecurity (SpiderLabs) |
| Email | `mail.networkwalks.com` on the same IP; SPF with soft-fail (`~all`) |
| DNSSEC | Unsigned |

### Task 1 - WHOIS

```bash
whois networkwalks.com
```

Retrieves public domain registration data. The output contains two records: the registry (VeriSign) record and the registrar (GoDaddy) record.

| Field | Value |
|---|---|
| Domain | NETWORKWALKS.COM |
| Registrar | GoDaddy.com, LLC (IANA ID 146) |
| Creation date | 2019-11-06 |
| Registry expiry date | 2027-11-06 |
| Last updated | 2025-11-12 |
| Name servers (registry record) | NS6135.HOSTGATOR.COM, NS6136.HOSTGATOR.COM |
| Name servers (registrar record) | The two above, plus NS29.DOMAINCONTROL.COM, NS30.DOMAINCONTROL.COM |
| Registrant | Domains By Proxy, LLC (privacy service, owner details hidden) |
| Domain status | clientDeleteProhibited, clientRenewProhibited, clientTransferProhibited, clientUpdateProhibited |
| DNSSEC | unsigned |

 
<img width="1920" height="1020" alt="WHOIS" src="https://github.com/user-attachments/assets/e17faefa-c057-400d-a968-7ec46d0c0fb9" />
<img width="1920" height="1020" alt="whois1" src="https://github.com/user-attachments/assets/c77eeb5c-d5ff-42f5-a2d1-83d3e71ca3ca" />

 


### Task 2 - WhatWeb

```bash
whatweb networkwalks.com
```

Fingerprints web technologies. `http://` returns `301 Moved Permanently` to `https://networkwalks.com/`, which returns `200 OK`.

| Item | Result |
|---|---|
| Web server | Apache |
| IP address | 192.232.216.135 |
| CMS | WordPress 7.1.4 |
| Plugin | WordPress Download Manager 3.3.76 |
| jQuery | 3.7.1 |
| Other | Google Tag Manager, HTML5, Open Graph, iframe usage |
| Cookie | `__wpdm_client` (HttpOnly) |
| Exposed contact email | info@networkwalks.com |
| Page title | Networkwalks Academy |
| Uncommon headers | permissions-policy, link, referrer-policy, x-endurance-cache-level, x-nginx-cache |

> **Note:** WhatWeb also reports `Bootstrap 7.1.4`, which is identical to the WordPress version. This is most likely a false positive (a version string read from a `?ver=` asset parameter), so it is not treated as a reliable finding.

 <img width="1920" height="1020" alt="whatweb" src="https://github.com/user-attachments/assets/3c7145a8-ab4b-403a-b23c-c3a36eafa3a6" />


### Task 3 - NSLookup

```bash
nslookup networkwalks.com
```

| Item | Result |
|---|---|
| DNS server used | 8.8.8.8#53 |
| Answer type | Non-authoritative |
| Resolved IP | 192.232.216.135 |

 <img width="1920" height="1020" alt="nslookup" src="https://github.com/user-attachments/assets/f3e08828-e671-4d8f-8577-2530b7c91f98" />


### Task 4 - HTTP response headers

```bash
curl -I https://networkwalks.com
```

Response: `HTTP/1.1 200 OK`

| Header | Value / meaning |
|---|---|
| Server | Apache |
| Content-Type | text/html; charset=UTF-8 |
| Link | WordPress REST API (`/wp-json/`) and shortlink exposed |
| Set-Cookie | `__wpdm_client` (path `/`, Secure, HttpOnly) |
| Permissions-Policy | `private-state-token-*` limited to self and Google / reCAPTCHA / Cloudflare / hCaptcha origins |
| Referrer-Policy | no-referrer-when-downgrade |
| X-Endurance-Cache-Level | 0 |
| X-nginx-cache | WordPress |

> **Observation:** No `Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options` or `X-Content-Type-Options` headers appear in this response.
<img width="1900" height="666" alt="curl -I" src="https://github.com/user-attachments/assets/6d3ea658-6e6d-4c91-8eec-4d1f2b859597" />

 

### Task 5 - Web Application Firewall detection

```bash
wafw00f networkwalks.com
```

| Item | Result |
|---|---|
| Tool version | WAFW00F 2.4.2 |
| Requests sent | 2 |
| Result | `https://networkwalks.com` is behind **ModSecurity (SpiderLabs)** WAF |

 <img width="1841" height="912" alt="waafw00f" src="https://github.com/user-attachments/assets/af4dfd57-d7ee-4c1d-bd8a-4dfce664f68f" />


### Task 6 - DNS enumeration

```bash
dnsrecon -d networkwalks.com
```

| Type | Record |
|---|---|
| SOA | ns6135.hostgator.com - 50.87.144.87 |
| NS | ns6136.hostgator.com - 192.232.216.131 |
| NS | ns6135.hostgator.com - 50.87.144.87 |
| MX | mail.networkwalks.com - 192.232.216.135 |
| A | networkwalks.com - 192.232.216.135 |
| TXT (SPF) | `v=spf1 +a +mx +ip4:50.87.144.87 +include:websitewelcome.com ~all` |
| TXT | Google site-verification record |
| SRV | `_autodiscover._tcp` -> `cpanelemaildiscovery.cpanel.net` port 443 (8 records, IPs in 184.94.203.x and 184.94.204.x) |

DNSRecon reported **8 records found** (the SRV records).

**Observations**
- Both name servers disclose their BIND version (`9.16.23-RH`).
- The DNSSEC query returned no answer, consistent with WHOIS showing DNSSEC as unsigned.

 
<img width="1832" height="896" alt="dnsrecon" src="https://github.com/user-attachments/assets/713fdb7c-9e9b-4427-b92c-b1295d7cbfd4" />


---

## Module 5 - Network Scanning with Zenmap

**Objective:** Discover live hosts on the local network using Zenmap/Nmap and visualise the result as a network topology.

### Task 1 - Download & install Zenmap

Zenmap/Nmap was downloaded and installed for the scanning lab.

 <img width="1660" height="921" alt="Screenshot 2026-11-16 150221" src="https://github.com/user-attachments/assets/5ed8b1ec-05a8-4e2a-9d56-f337a2265f8c" />
 <img width="750" height="548" alt="nmap-installed" src="https://github.com/user-attachments/assets/20896a06-665b-4c6a-87e7-b2ae7f6ca38c" />


### Task 2 - Local IP address & LAN subnet

| Parameter | Value |
|---|---|
| Local IPv4 address | 192.168.0.106 |
| Subnet mask | 255.255.255.0 |
| Default gateway | 192.168.0.1 |
| LAN subnet | 192.168.0.0/24 |

 <img width="1001" height="528" alt="Screenshot 2026-11-16 150756" src="https://github.com/user-attachments/assets/fca44197-8244-49ed-9d8d-da7a75667e59" />


### Task 3 - Find live hosts

Zenmap **Ping scan** profile (equivalent to `nmap -sn`) against the whole LAN subnet:

```
192.168.0.0/24
```

 <img width="1001" height="502" alt="live host " src="https://github.com/user-attachments/assets/736d6b94-5b7b-4fbc-b81d-9d82382f077c" />


### Task 4 - Number of live hosts

**2 live host** found in the subnet.

### Task 5 - IP addresses of live hosts

| # | IP address |
|---|---|
| 1 | 192.168.0.106 (the local machine) |

### Task 6 - Network topology

Zenmap's Topology view was used to visualise the discovered host.

 <img width="975" height="411" alt="Screenshot 2026-11-16 152016" src="https://github.com/user-attachments/assets/1e5daadd-a5ca-4ba7-89b9-4e39fbd025bc" />




## Tools Used

- **Module 5:** Zenmap, Nmap
- **Module 1:** Kali Linux, whois, WhatWeb, nslookup, cURL, WAFW00F, DNSRecon

## Skills Practiced

- Network discovery and host identification
- Network topology visualisation
- Domain footprinting (WHOIS analysis)
- Web technology fingerprinting
- DNS enumeration and DNS record analysis
- HTTP header analysis
- WAF detection
