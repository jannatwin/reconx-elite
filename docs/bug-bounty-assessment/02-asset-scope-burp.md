# In-scope assets and Burp configuration

Derived from [01-policy-intake.md](01-policy-intake.md). Keep this file updated if the program changes scope.

## Master asset list

**In-scope hostnames** (one per line; no trailing dots):

```
# example.com
# app.example.com
# api.example.com
```

**In-scope URL prefixes** (if the program scopes by path):

| Base URL | Notes |
|----------|--------|
| | |

**Out-of-scope (do not proxy or request)** — copy from policy:

```
```

## Burp Suite: Target scope

1. Open **Target → Scope**.
2. Under **Include in scope**, add:
   - Each **exact hostname** from the master list, or
   - A **wildcard** only if the program explicitly allows `*.target.com`-style scope.
3. Under **Exclude from scope**, add:
   - Third-party scripts/CDNs that are out of scope (e.g. `*.google-analytics.com`) if you want a clean sitemap.
4. Enable **Use advanced scope control** if you need path-based limits (rare; follow program wording).

## Burp: spider / scan discipline

- Set **Spider** and any automated tasks to **respect scope** (only in-scope URLs).
- Do not run **active scanner** or high-volume Intruder against production unless the program permits it.

## Forbidden techniques reminder

List anything the program forbids that affects tooling:

| Technique | Allowed? | Notes |
|-----------|----------|--------|
| Port scanning | | |
| Subdomain brute force | | |
| Password spraying | | |
| Load / DoS-style testing | | |

---

**Next step:** Run recon per [03-recon-runbook.md](03-recon-runbook.md).
