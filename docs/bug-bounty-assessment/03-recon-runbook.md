# Reconnaissance runbook (passive first, then active if allowed)

Align every command with [01-policy-intake.md](01-policy-intake.md) (automation and scope). Use a **dedicated working directory** per program; keep raw logs for triage and duplicate disputes.

## 0. Working layout

Suggested structure:

```
bb-<program-slug>/
  notes.md
  passive/
  active/          # only if policy allows
  deduped/
  live/
```

## 1. Passive subdomain / asset discovery

Run **passive** sources first (lower direct impact on target infrastructure). Examples (adjust flags to your install):

- **Certificate transparency:** query `crt.sh` for the root domain (browser or API), export names.
- **subfinder** (passive resolvers): `subfinder -d <domain> -silent -o passive/subfinder.txt`
- **Other passive tools** as you prefer (sublist3r, findomain, etc.), always **output to separate files**.

Combine passive outputs:

```bash
# Unix-like shell (Git Bash, WSL)
cat passive/*.txt | sort -u > deduped/subdomains-all.txt
```

On **PowerShell**:

```powershell
Get-ChildItem passive\*.txt | Get-Content | Sort-Object -Unique | Set-Content deduped\subdomains-all.txt
```

## 2. Active enumeration (only if in scope and allowed)

If the program permits DNS or HTTP brute force:

- **ffuf / gobuster** against DNS or vhost wordlists — throttle to avoid looking like a DoS.
- Save outputs under `active/` and merge into `deduped/subdomains-all.txt` (dedupe again).

## 3. Resolution

Resolve names you intend to probe (tooling of choice: `massdns`, `dnsx`, etc.). Drop names that do not resolve if you need a smaller set.

## 4. Live host triage (httpx)

Probe **only hostnames that are in-scope** (filter `deduped/subdomains-all.txt` against your master list if wildcards are not used).

Example:

```bash
httpx -l deduped/subdomains-all.txt -o live/httpx.txt -title -tech-detect -status-code -content-length -server
```

Review `live/httpx.txt` for status codes, titles, stack fingerprints, and odd ports (if httpx configured to probe them).

## 5. Screenshots (optional triage)

**gowitness** or **eyewitness** against the live list — helps spot admin panels, staging, default pages. Confirm bulk requests are acceptable under program rules.

## 6. URL collection

For each **in-scope** live host:

- **Archives:** `gau`, `waybackurls` (domain-filtered).
- **Crawl:** `katana` (with JS parsing if needed), `hakrawler`, or Burp Spider **scoped** to in-scope hosts.

Merge and deduplicate:

```bash
cat urls-*.txt | sort -u > deduped/urls-all.txt
```

Extract **URLs with query parameters** for injection testing:

```bash
grep '[?]' deduped/urls-all.txt > deduped/urls-with-params.txt
```

## 7. JavaScript review (high yield)

From Burp sitemap or URL list, collect `.js` asset URLs **for in-scope hosts only**. Download locally, then run **linkfinder** / **SecretFinder** / **trufflehog** (or equivalent) on allowed content. Manually grep for: `api`, `token`, `secret`, `admin`, `internal`, `graphql`, `oauth`.

---

**Next step:** Map the application in [04-attack-surface-map.md](04-attack-surface-map.md).
