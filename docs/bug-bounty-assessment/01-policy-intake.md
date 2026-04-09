# Policy intake (complete before any testing)

Use this checklist when you start work on a **new** external bug bounty program. Paste authoritative text from the program page; do not rely on memory.

## Program identity

| Field | Value |
|--------|--------|
| Platform | (e.g. HackerOne / Bugcrowd / Intigriti / other) |
| Program URL | |
| Program name | |
| Date reviewed | |

## In-scope assets

Copy from the official scope section:

- **Domains / subdomains** (exact strings; note wildcards e.g. `*.example.com`):
  - 
- **Mobile apps** (package IDs / store links if listed):
  - 
- **API base URLs** (if explicitly listed):
  - 
- **IP ranges / CIDR** (only if in scope):
  - 

## Out-of-scope / forbidden

List exclusions that affect **what you test** or **how**:

- **Explicitly out-of-scope assets**:
  - 
- **Excluded vulnerability classes** (if any):
  - 
- **Automation / scanning policy** (allowed, restricted, requires permission, rate limits):
  - 
- **Social engineering / physical** (usually forbidden):
  - 

## Rewards and severity

| Field | Notes |
|--------|--------|
| Minimum severity for reward (if stated) | |
| CVSS or platform severity model | |
| Bonus focus areas (if announced) | |

## Disclosure and duplicates

| Field | Notes |
|--------|--------|
| Where to read disclosed / fixed reports (e.g. Hacktivity) | |
| Duplicate policy summary | |

## Safe harbor / legal

| Field | Notes |
|--------|--------|
| Safe harbor statement present? | Yes / No |
| Reporting channel (only use official form/email in policy) | |

## Sign-off

Before recon or testing, confirm:

- [ ] Every hostname I will touch appears in **in-scope** (or is a dependency explicitly allowed).
- [ ] My planned techniques (subdomain enum, port scan, active crawl, etc.) match **program rules**.
- [ ] I will use **only my own test accounts** and minimize access to others’ data.

---

**Next step:** Transfer in-scope hostnames and rules into [02-asset-scope-burp.md](02-asset-scope-burp.md).
