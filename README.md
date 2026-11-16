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

 Networkwalks-Week2-Cybersecurity-Lab/WHOIS.png


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

![WhatWeb](screenshots/module-1/whatweb.png)

### Task 3 - NSLookup

```bash
nslookup networkwalks.com
```

| Item | Result |
|---|---|
| DNS server used | 8.8.8.8#53 |
| Answer type | Non-authoritative |
| Resolved IP | 192.232.216.135 |

![NSLookup](screenshots/module-1/nslookup.png)

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

![cURL headers](screenshots/module-1/curl-headers.png)

### Task 5 - Web Application Firewall detection

```bash
wafw00f networkwalks.com
```

| Item | Result |
|---|---|
| Tool version | WAFW00F 2.4.2 |
| Requests sent | 2 |
| Result | `https://networkwalks.com` is behind **ModSecurity (SpiderLabs)** WAF |

![WAFW00F](screenshots/module-1/wafw00f.png)

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

![DNSRecon](screenshots/module-1/dnsrecon.png)

---

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
